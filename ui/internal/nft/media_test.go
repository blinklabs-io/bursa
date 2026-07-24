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
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"testing"
)

func validTestPNG() []byte {
	var buf bytes.Buffer
	img := image.NewNRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.NRGBA{R: 0xff, A: 0xff})
	if err := png.Encode(&buf, img); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func pngWithDimensions(width, height uint32) []byte {
	data := validTestPNG()
	binary.BigEndian.PutUint32(data[16:20], width)
	binary.BigEndian.PutUint32(data[20:24], height)
	binary.BigEndian.PutUint32(data[29:33], crc32.ChecksumIEEE(data[12:29]))
	return data
}

func TestValidateImageRejectsLargeDecodedPNG(t *testing.T) {
	err := validateImage(pngWithDimensions(5000, 5000))
	if !errors.Is(err, ErrUnsafeImage) {
		t.Fatalf("validateImage large PNG = %v, want ErrUnsafeImage", err)
	}
}

func TestValidateImageRejectsAnimatedGIFTotalResourceCost(t *testing.T) {
	data := []byte{
		'G', 'I', 'F', '8', '9', 'a',
		0x00, 0x04, 0x00, 0x04, // 1024 x 1024 logical screen
		0x80, 0x00, 0x00, // global two-entry color table follows
		0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
	}
	for range 17 { // 17 * 1024 * 1024 * 4 > 64 MiB
		data = append(data,
			0x2c, 0, 0, 0, 0, 0x00, 0x04, 0x00, 0x04, 0,
			2, 2, 0x44, 0x01, 0,
		)
	}
	data = append(data, 0x3b)
	err := validateImage(data)
	if !errors.Is(err, ErrUnsafeImage) {
		t.Fatalf("validateImage animated GIF = %v, want ErrUnsafeImage", err)
	}
}

func TestValidateImageChargesGIFCanvasPerTinyFrame(t *testing.T) {
	data := []byte{
		'G', 'I', 'F', '8', '9', 'a',
		0x00, 0x04, 0x00, 0x04, // 1024 x 1024 logical screen
		0x80, 0x00, 0x00,
		0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
	}
	for range 17 {
		data = append(data,
			0x2c, 0, 0, 0, 0, 1, 0, 1, 0, 0,
			2, 2, 0x44, 0x01, 0,
		)
	}
	data = append(data, 0x3b)
	err := validateImage(data)
	if !errors.Is(err, ErrUnsafeImage) {
		t.Fatalf("validateImage tiny-frame GIF = %v, want ErrUnsafeImage", err)
	}
}

func TestPNGResourceCostChargesCanvasPerTinyFrame(t *testing.T) {
	const canvasPixels = uint64(1024 * 1024)
	data := validTestPNG()
	iend := bytes.LastIndex(data, []byte("IEND")) - 4
	if iend < 0 {
		t.Fatal("test PNG has no IEND")
	}
	var chunks []byte
	for sequence := uint32(0); sequence < 17; sequence++ {
		payload := make([]byte, 26)
		binary.BigEndian.PutUint32(payload[0:4], sequence)
		binary.BigEndian.PutUint32(payload[4:8], 1)
		binary.BigEndian.PutUint32(payload[8:12], 1)
		var chunk bytes.Buffer
		_ = binary.Write(&chunk, binary.BigEndian, uint32(len(payload)))
		chunk.WriteString("fcTL")
		chunk.Write(payload)
		_ = binary.Write(&chunk, binary.BigEndian, crc32.ChecksumIEEE(chunk.Bytes()[4:]))
		chunks = append(chunks, chunk.Bytes()...)
	}
	data = append(append(append([]byte(nil), data[:iend]...), chunks...), data[iend:]...)
	cost, err := pngResourceCost(data, canvasPixels)
	if err != nil {
		t.Fatalf("pngResourceCost: %v", err)
	}
	if cost != 17*canvasPixels {
		t.Fatalf("APNG resource cost = %d, want %d", cost, 17*canvasPixels)
	}
}

func TestValidateImageRejectsOversizedGIFFrameAxis(t *testing.T) {
	data := []byte{
		'G', 'I', 'F', '8', '9', 'a',
		1, 0, 1, 0, 0x80, 0, 0,
		0, 0, 0, 0xff, 0xff, 0xff,
		0x2c, 0, 0, 0, 0, 0x01, 0x20, 1, 0, 0, // 8193 x 1
		2, 2, 0x44, 0x01, 0, 0x3b,
	}
	err := validateImage(data)
	if !errors.Is(err, ErrUnsafeImage) {
		t.Fatalf("validateImage wide GIF frame = %v, want ErrUnsafeImage", err)
	}
}

func TestWebPResourceCostRejectsAnimationTotalAndFrameAxis(t *testing.T) {
	makeWebP := func(frameWidth, frameHeight uint32, frameCount int) []byte {
		data := []byte{'R', 'I', 'F', 'F', 0, 0, 0, 0, 'W', 'E', 'B', 'P'}
		// VP8X canvas is 1024 x 1024.
		data = append(data, 'V', 'P', '8', 'X', 10, 0, 0, 0, 0x02, 0, 0, 0, 0xff, 3, 0, 0xff, 3, 0)
		for range frameCount {
			chunk := make([]byte, 16)
			w := frameWidth - 1
			h := frameHeight - 1
			chunk[6], chunk[7], chunk[8] = byte(w), byte(w>>8), byte(w>>16)
			chunk[9], chunk[10], chunk[11] = byte(h), byte(h>>8), byte(h>>16)
			data = append(data, 'A', 'N', 'M', 'F', 16, 0, 0, 0)
			data = append(data, chunk...)
		}
		binary.LittleEndian.PutUint32(data[4:8], uint32(len(data)-8))
		return data
	}

	t.Run("total frame cost", func(t *testing.T) {
		err := validateImage(makeWebP(1024, 1024, 17))
		if !errors.Is(err, ErrUnsafeImage) {
			t.Fatalf("validateImage animated WebP = %v, want ErrUnsafeImage", err)
		}
	})
	t.Run("canvas charged per tiny frame", func(t *testing.T) {
		err := validateImage(makeWebP(1, 1, 17))
		if !errors.Is(err, ErrUnsafeImage) {
			t.Fatalf("validateImage tiny-frame WebP = %v, want ErrUnsafeImage", err)
		}
	})
	t.Run("frame axis", func(t *testing.T) {
		err := validateImage(makeWebP(maxImageDimension+1, 1, 1))
		if !errors.Is(err, ErrUnsafeImage) {
			t.Fatalf("validateImage wide WebP frame = %v, want ErrUnsafeImage", err)
		}
	})
}
