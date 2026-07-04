// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nft

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"net/http"
)

// ErrUnsafeImage identifies media that is not a supported, resource-bounded
// raster image. Callers must not pass such bytes to a browser image decoder.
var ErrUnsafeImage = errors.New("nft: unsafe image")

const (
	// Bound both axes as well as total pixels. An extremely thin image can
	// otherwise pass a pixel-only check while still stressing browser layout
	// and decoder internals.
	maxImageDimension = 8192

	// This is an upper bound on decoded RGBA storage, not compressed transfer
	// size. For animated formats, every frame contributes to the budget.
	maxDecodedImageBytes uint64 = 64 << 20 // 64 MiB
	bytesPerPixel               = 4
)

func validateImage(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("%w: empty media", ErrUnsafeImage)
	}
	if len(data) > maxImageBytes {
		return fmt.Errorf("%w: compressed image %d bytes exceeds cap %d", ErrUnsafeImage, len(data), maxImageBytes)
	}

	contentType := http.DetectContentType(data)
	if !allowedImageContentType(contentType) {
		return fmt.Errorf("%w: unsupported media type %q", ErrUnsafeImage, contentType)
	}

	var width, height uint32
	var pixels uint64
	var err error
	switch contentType {
	case "image/webp":
		width, height, pixels, err = webpResourceCost(data)
	default:
		var cfg image.Config
		cfg, _, err = image.DecodeConfig(bytes.NewReader(data))
		if err == nil {
			width, height = uint32(cfg.Width), uint32(cfg.Height)
			pixels = uint64(width) * uint64(height)
			switch contentType {
			case "image/gif":
				pixels, err = gifResourceCost(data)
			case "image/png":
				pixels, err = pngResourceCost(data, pixels)
			}
		}
	}
	if err != nil {
		return fmt.Errorf("%w: invalid %s: %v", ErrUnsafeImage, contentType, err)
	}
	if width == 0 || height == 0 {
		return fmt.Errorf("%w: image has zero dimensions", ErrUnsafeImage)
	}
	if width > maxImageDimension || height > maxImageDimension {
		return fmt.Errorf(
			"%w: dimensions %dx%d exceed %dx%d",
			ErrUnsafeImage,
			width,
			height,
			maxImageDimension,
			maxImageDimension,
		)
	}
	if pixels > maxDecodedImageBytes/bytesPerPixel {
		return fmt.Errorf(
			"%w: decoded image requires at least %d bytes, cap is %d",
			ErrUnsafeImage,
			pixels*bytesPerPixel,
			maxDecodedImageBytes,
		)
	}
	return nil
}

// gifResourceCost walks block framing without decompressing pixels. Decoding
// all frames merely to inspect them would itself trigger the allocation this
// check is intended to prevent.
func gifResourceCost(data []byte) (uint64, error) {
	if len(data) < 13 {
		return 0, errors.New("short GIF header")
	}
	pos := 13
	canvasPixels := uint64(binary.LittleEndian.Uint16(data[6:8])) *
		uint64(binary.LittleEndian.Uint16(data[8:10]))
	if data[10]&0x80 != 0 {
		pos += 3 * (1 << ((data[10] & 0x07) + 1))
	}
	var pixels uint64
	for pos < len(data) {
		switch data[pos] {
		case 0x3b: // trailer
			if pixels == 0 {
				// A decoder still allocates the logical screen for a GIF with
				// no image descriptor.
				return canvasPixels, nil
			}
			return pixels, nil
		case 0x21: // extension: label followed by data sub-blocks
			pos += 2
			var err error
			pos, err = skipGIFSubBlocks(data, pos)
			if err != nil {
				return 0, err
			}
		case 0x2c: // image descriptor
			if pos+10 > len(data) {
				return 0, errors.New("short GIF image descriptor")
			}
			w := binary.LittleEndian.Uint16(data[pos+5 : pos+7])
			h := binary.LittleEndian.Uint16(data[pos+7 : pos+9])
			if w == 0 || h == 0 {
				return 0, errors.New("zero-sized GIF frame")
			}
			if w > maxImageDimension || h > maxImageDimension {
				return 0, fmt.Errorf("GIF frame dimensions %dx%d exceed limit", w, h)
			}
			// Animation compositing may retain a full logical canvas per
			// displayed frame even when this frame updates a tiny rectangle.
			framePixels := uint64(w) * uint64(h)
			if framePixels < canvasPixels {
				framePixels = canvasPixels
			}
			pixels += framePixels
			packed := data[pos+9]
			pos += 10
			if packed&0x80 != 0 {
				pos += 3 * (1 << ((packed & 0x07) + 1))
			}
			if pos >= len(data) {
				return 0, errors.New("missing GIF LZW code size")
			}
			pos++ // LZW minimum code size
			var err error
			pos, err = skipGIFSubBlocks(data, pos)
			if err != nil {
				return 0, err
			}
		default:
			return 0, fmt.Errorf("unexpected GIF block 0x%02x", data[pos])
		}
	}
	return 0, errors.New("missing GIF trailer")
}

func skipGIFSubBlocks(data []byte, pos int) (int, error) {
	for {
		if pos >= len(data) {
			return 0, errors.New("truncated GIF sub-block")
		}
		size := int(data[pos])
		pos++
		if size == 0 {
			return pos, nil
		}
		if size > len(data)-pos {
			return 0, errors.New("truncated GIF sub-block data")
		}
		pos += size
	}
}

// pngResourceCost accounts for APNG frames (fcTL chunks). Static PNGs have no
// fcTL chunk and use the IHDR dimensions supplied by image.DecodeConfig.
func pngResourceCost(data []byte, staticPixels uint64) (uint64, error) {
	if len(data) < 8 || !bytes.Equal(data[:8], []byte("\x89PNG\r\n\x1a\n")) {
		return 0, errors.New("bad PNG signature")
	}
	pos := 8
	var pixels uint64
	var frames int
	for pos+12 <= len(data) {
		size := uint64(binary.BigEndian.Uint32(data[pos : pos+4]))
		if size > uint64(len(data)-pos-12) {
			return 0, errors.New("truncated PNG chunk")
		}
		typ := string(data[pos+4 : pos+8])
		if typ == "fcTL" {
			if size != 26 {
				return 0, errors.New("invalid APNG frame-control chunk")
			}
			w := binary.BigEndian.Uint32(data[pos+12 : pos+16])
			h := binary.BigEndian.Uint32(data[pos+16 : pos+20])
			if w == 0 || h == 0 {
				return 0, errors.New("zero-sized APNG frame")
			}
			if w > maxImageDimension || h > maxImageDimension {
				return 0, fmt.Errorf("APNG frame dimensions %dx%d exceed limit", w, h)
			}
			// APNG frames are composited onto the IHDR canvas. Charge at least
			// one complete canvas allocation for every frame.
			framePixels := uint64(w) * uint64(h)
			if framePixels < staticPixels {
				framePixels = staticPixels
			}
			pixels += framePixels
			frames++
		}
		pos += 12 + int(size)
		if typ == "IEND" {
			if frames == 0 {
				return staticPixels, nil
			}
			return pixels, nil
		}
	}
	return 0, errors.New("missing PNG end chunk")
}

func webpResourceCost(data []byte) (width, height uint32, pixels uint64, err error) {
	if len(data) < 20 || string(data[:4]) != "RIFF" || string(data[8:12]) != "WEBP" {
		return 0, 0, 0, errors.New("bad WebP header")
	}
	declared := uint64(binary.LittleEndian.Uint32(data[4:8])) + 8
	if declared > uint64(len(data)) {
		return 0, 0, 0, errors.New("truncated WebP container")
	}
	pos := 12
	var framePixels uint64
	var frameCount uint64
	var stillPixels uint64
	for pos+8 <= int(declared) {
		typ := string(data[pos : pos+4])
		size := int(binary.LittleEndian.Uint32(data[pos+4 : pos+8]))
		pos += 8
		if size < 0 || size > int(declared)-pos {
			return 0, 0, 0, errors.New("truncated WebP chunk")
		}
		chunk := data[pos : pos+size]
		switch typ {
		case "VP8X":
			if len(chunk) < 10 {
				return 0, 0, 0, errors.New("short WebP extended header")
			}
			width = uint32(chunk[4]) | uint32(chunk[5])<<8 | uint32(chunk[6])<<16
			height = uint32(chunk[7]) | uint32(chunk[8])<<8 | uint32(chunk[9])<<16
			width++
			height++
		case "VP8 ":
			w, h, dimensionErr := webpBitstreamDimensions(typ, chunk)
			if dimensionErr != nil {
				return 0, 0, 0, dimensionErr
			}
			if width == 0 {
				width, height = w, h
			}
			stillPixels = uint64(w) * uint64(h)
		case "VP8L":
			w, h, dimensionErr := webpBitstreamDimensions(typ, chunk)
			if dimensionErr != nil {
				return 0, 0, 0, dimensionErr
			}
			if width == 0 {
				width, height = w, h
			}
			stillPixels = uint64(w) * uint64(h)
		case "ANMF":
			if len(chunk) < 16 {
				return 0, 0, 0, errors.New("short animated WebP frame")
			}
			w := 1 + (uint32(chunk[6]) | uint32(chunk[7])<<8 | uint32(chunk[8])<<16)
			h := 1 + (uint32(chunk[9]) | uint32(chunk[10])<<8 | uint32(chunk[11])<<16)
			if w > maxImageDimension || h > maxImageDimension {
				return 0, 0, 0, fmt.Errorf("animated WebP frame dimensions %dx%d exceed limit", w, h)
			}
			cost := uint64(w) * uint64(h)
			// Validate the embedded VP8/VP8L dimensions too. A hostile
			// bitstream must not induce a large allocation before the decoder
			// notices that it disagrees with the ANMF rectangle.
			for nested := 16; nested+8 <= len(chunk); {
				nestedType := string(chunk[nested : nested+4])
				nestedSize := int(binary.LittleEndian.Uint32(chunk[nested+4 : nested+8]))
				nested += 8
				if nestedSize > len(chunk)-nested {
					return 0, 0, 0, errors.New("truncated animated WebP subchunk")
				}
				if nestedType == "VP8 " || nestedType == "VP8L" {
					innerW, innerH, dimensionErr := webpBitstreamDimensions(
						nestedType,
						chunk[nested:nested+nestedSize],
					)
					if dimensionErr != nil {
						return 0, 0, 0, dimensionErr
					}
					if inner := uint64(innerW) * uint64(innerH); inner > cost {
						cost = inner
					}
				}
				nested += nestedSize + nestedSize&1
			}
			framePixels += cost
			frameCount++
		}
		pos += size + size&1
	}
	if width == 0 || height == 0 {
		return 0, 0, 0, errors.New("missing WebP dimensions")
	}
	if frameCount == 0 {
		framePixels = uint64(width) * uint64(height)
		if stillPixels > framePixels {
			framePixels = stillPixels
		}
	} else if canvasFrames := uint64(width) * uint64(height) * frameCount; framePixels < canvasFrames {
		// Animated WebP subframes are composited on the VP8X canvas.
		framePixels = canvasFrames
	}
	return width, height, framePixels, nil
}

func webpBitstreamDimensions(typ string, chunk []byte) (uint32, uint32, error) {
	var width, height uint32
	switch typ {
	case "VP8 ":
		if len(chunk) < 10 || !bytes.Equal(chunk[3:6], []byte{0x9d, 0x01, 0x2a}) {
			return 0, 0, errors.New("invalid WebP lossy frame header")
		}
		width = uint32(binary.LittleEndian.Uint16(chunk[6:8]) & 0x3fff)
		height = uint32(binary.LittleEndian.Uint16(chunk[8:10]) & 0x3fff)
	case "VP8L":
		if len(chunk) < 5 || chunk[0] != 0x2f {
			return 0, 0, errors.New("invalid WebP lossless frame header")
		}
		bits := binary.LittleEndian.Uint32(chunk[1:5])
		width = 1 + bits&0x3fff
		height = 1 + (bits>>14)&0x3fff
	default:
		return 0, 0, errors.New("unknown WebP bitstream type")
	}
	if width == 0 || height == 0 {
		return 0, 0, errors.New("zero-sized WebP bitstream")
	}
	if width > maxImageDimension || height > maxImageDimension {
		return 0, 0, fmt.Errorf("WebP bitstream dimensions %dx%d exceed limit", width, height)
	}
	return width, height, nil
}
