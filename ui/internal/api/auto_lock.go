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

package api

import (
	"sync"
	"time"
)

type autoLockTimer interface {
	Stop() bool
}

type autoLockRuntime struct {
	now       func() time.Time
	afterFunc func(time.Duration, func()) autoLockTimer
}

func defaultAutoLockRuntime() autoLockRuntime {
	return autoLockRuntime{
		now: time.Now,
		afterFunc: func(d time.Duration, f func()) autoLockTimer {
			return time.AfterFunc(d, f)
		},
	}
}

// autoLockController owns the unlocked vault's idle deadline. The deadline is
// wall-clock based so Check catches time spent while a mobile process was
// suspended, while the timer enforces it continuously whenever the process is
// running.
type autoLockController struct {
	mu         sync.Mutex
	vault      Vault
	settings   SettingsController
	onLock     func()
	runtime    autoLockRuntime
	timer      autoLockTimer
	deadlineNs int64
	generation uint64
}

func newAutoLockController(
	vault Vault,
	settings SettingsController,
	onLock func(),
	runtime autoLockRuntime,
) *autoLockController {
	return &autoLockController{
		vault:    vault,
		settings: settings,
		onLock:   onLock,
		runtime:  runtime,
	}
}

func (c *autoLockController) Arm() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopLocked()
	c.armLocked()
}

func (c *autoLockController) Activity() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.vault.Locked() {
		return false
	}
	now := c.runtime.now()
	if c.deadlineNs != 0 && now.UnixNano() >= c.deadlineNs {
		c.expireLocked()
		return false
	}
	minutes := c.settings.AutoLockMinutes()
	if minutes <= 0 {
		c.stopLocked()
		return true
	}
	d := time.Duration(minutes) * time.Minute
	c.deadlineNs = now.Add(d).UnixNano()
	if c.timer == nil {
		c.scheduleLocked(d)
	}
	return true
}

func (c *autoLockController) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopLocked()
}

// Check expires a wall-clock deadline that elapsed while the process was
// suspended. Mobile lifecycle callbacks invoke it before reconnecting the node.
func (c *autoLockController) Check() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.deadlineNs == 0 {
		return
	}
	if c.vault.Locked() {
		c.stopLocked()
		return
	}
	if c.runtime.now().UnixNano() < c.deadlineNs {
		return
	}
	c.expireLocked()
}

func (c *autoLockController) armLocked() {
	minutes := c.settings.AutoLockMinutes()
	if minutes <= 0 || c.vault.Locked() {
		return
	}
	d := time.Duration(minutes) * time.Minute
	c.deadlineNs = c.runtime.now().Add(d).UnixNano()
	c.scheduleLocked(d)
}

func (c *autoLockController) scheduleLocked(d time.Duration) {
	c.generation++
	generation := c.generation
	c.timer = c.runtime.afterFunc(d, func() {
		c.expire(generation)
	})
}

func (c *autoLockController) expire(generation uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if generation != c.generation || c.deadlineNs == 0 {
		return
	}
	remaining := time.Duration(c.deadlineNs - c.runtime.now().UnixNano())
	if remaining > 0 {
		c.timer = nil
		c.scheduleLocked(remaining)
		return
	}
	c.expireLocked()
}

func (c *autoLockController) expireLocked() {
	c.stopLocked()
	c.vault.Lock()
	c.onLock()
}

func (c *autoLockController) stopLocked() {
	c.generation++
	c.deadlineNs = 0
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
}
