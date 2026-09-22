/**
 * @file peripherals.h
 * @brief OpenKey Peripheral Manager (WS2812B NeoPixel & Physical Button Verification)
 * @version 1.0.0
 * 
 * Hardware Target: Waveshare ESP32-S3-Zero
 * - WS2812B NeoPixel on GPIO 21
 * - Physical Boot Button on GPIO 0
 */

#pragma once

#include <Arduino.h>
#include <esp_timer.h>

#define NEOPIXEL_PIN        21
#define BUTTON_BOOT_PIN     0
#define PRESENCE_TIMEOUT_MS 15000 // 15 seconds per FIDO2 specification
#define MAX_LED_BRIGHTNESS  60    // Reduced brightness (60 out of 255) for comfortable viewing

namespace OpenKey {
namespace Peripherals {

enum class LedState {
    STANDBY_GREEN,          // Solid Green (Brightness 60): Key ready & idle
    CHALLENGE_BLUE,         // Slow Heartbeat Blue (Brightness 60): Verification challenge
    PHISHING_ALERT_RED,     // Rapid Flashing Red (Brightness 150): Unknown/phishing domain
    COUNTDOWN_YELLOW,       // Air-Gapped Wipe Countdown Phase 1
    COUNTDOWN_RED,          // Air-Gapped Wipe Countdown Phase 2
    COUNTDOWN_WHITE,        // Air-Gapped Wipe Countdown Phase 3 (Rapid White)
    SUCCESS_GREEN,          // Flash Green: Cryptographic operation authorized
    ERROR_RED,              // Solid Red: Auth failed, timeout, or error
    OFF
};

class PeripheralManager {
private:
    LedState current_state;
    uint32_t challenge_start_time;
    volatile bool button_pressed;

    void set_rgb_explicit(uint8_t r, uint8_t g, uint8_t b, uint8_t brightness) {
        uint8_t scaled_r = (uint16_t)r * brightness / 255;
        uint8_t scaled_g = (uint16_t)g * brightness / 255;
        uint8_t scaled_b = (uint16_t)b * brightness / 255;

        #ifdef RGB_BUILTIN
        rgbLedWrite(NEOPIXEL_PIN, scaled_r, scaled_g, scaled_b);
        #else
        neopixelWrite(NEOPIXEL_PIN, scaled_r, scaled_g, scaled_b);
        #endif
    }

    void set_rgb_raw(uint8_t r, uint8_t g, uint8_t b) {
        set_rgb_explicit(r, g, b, MAX_LED_BRIGHTNESS);
    }

public:
    PeripheralManager() : current_state(LedState::STANDBY_GREEN),
                          challenge_start_time(0),
                          button_pressed(false) {}

    void init() {
        pinMode(BUTTON_BOOT_PIN, INPUT_PULLUP);
        set_state(LedState::STANDBY_GREEN);
    }

    void set_state(LedState state) {
        current_state = state;
        switch (current_state) {
            case LedState::STANDBY_GREEN:
                set_rgb_raw(0, 255, 0); // Solid emerald green (Brightness 60)
                break;
            case LedState::CHALLENGE_BLUE:
                challenge_start_time = millis();
                set_rgb_raw(0, 0, 30);  // Begin heartbeat blue
                break;
            case LedState::PHISHING_ALERT_RED:
                set_rgb_explicit(255, 0, 0, 150); // High-intensity red alert (Brightness 150)
                break;
            case LedState::COUNTDOWN_YELLOW:
                set_rgb_raw(255, 180, 0);
                break;
            case LedState::COUNTDOWN_RED:
                set_rgb_explicit(255, 0, 0, 100);
                break;
            case LedState::COUNTDOWN_WHITE:
                set_rgb_explicit(255, 255, 255, 150);
                break;
            case LedState::SUCCESS_GREEN:
                set_rgb_raw(0, 255, 0); // Flash green
                break;
            case LedState::ERROR_RED:
                set_rgb_raw(255, 0, 0); // Solid red
                break;
            case LedState::OFF:
                set_rgb_raw(0, 0, 0);
                break;
        }
    }

    /**
     * @brief High-intensity rapid flashing red alert for unknown or phishing domains
     * Flashes vibrant red at brightness 150 with an aggressive 80ms strobe
     */
    void flash_phishing_alert(uint32_t duration_ms = 1600) {
        uint32_t start = millis();
        while (millis() - start < duration_ms) {
            set_rgb_explicit(255, 0, 0, 150); // Flashing Red (Brightness 150)
            delay(80);
            set_rgb_explicit(0, 0, 0, 0);
            delay(80);
        }
        set_state(LedState::STANDBY_GREEN);
    }

    /**
     * @brief Periodic non-blocking service loop for animated LED patterns
     * Implements slow biological heartbeat rhythm in Blue (Brightness 60 max)
     */
    void update() {
        uint32_t now = millis();
        if (current_state == LedState::CHALLENGE_BLUE) {
            // 1200ms slow heartbeat rhythm: double-pulse (lub-dub) followed by rest
            uint32_t phase = (now - challenge_start_time) % 1200;
            uint8_t intensity;
            if (phase < 150) {
                // First beat (lub) rising
                intensity = 20 + (uint32_t)(255 - 20) * phase / 150;
            } else if (phase < 300) {
                // First beat falling
                intensity = 255 - (uint32_t)(255 - 70) * (phase - 150) / 150;
            } else if (phase < 450) {
                // Second beat (dub) rising
                intensity = 70 + (uint32_t)(255 - 70) * (phase - 300) / 150;
            } else if (phase < 750) {
                // Second beat decaying
                intensity = 255 - (uint32_t)(255 - 20) * (phase - 450) / 300;
            } else {
                // Rest period
                intensity = 20;
            }
            set_rgb_raw(0, 0, intensity); // Heartbeat in Blue (Brightness 60)
        }
    }

    /**
     * @brief User Presence Verification Loop
     * Pulses slow heartbeat rhythm in Blue (Brightness 60) while awaiting touch
     */
    bool verify_user_presence(void (*keepalive_cb)(uint32_t cid) = nullptr, uint32_t cid = 0,
                              uint32_t timeout_ms = PRESENCE_TIMEOUT_MS) {
        set_state(LedState::CHALLENGE_BLUE);
        uint32_t start_time = millis();
        uint32_t last_keepalive = millis();
        bool user_present = false;

        while (millis() - start_time < timeout_ms) {
            update();

            // Dispatch CTAPHID_KEEPALIVE to host every 100ms
            if (keepalive_cb && cid != 0 && (millis() - last_keepalive >= 100)) {
                last_keepalive = millis();
                keepalive_cb(cid);
            }

            // Active-low button check with debouncing
            if (digitalRead(BUTTON_BOOT_PIN) == LOW) {
                delay(20); // Debounce
                if (digitalRead(BUTTON_BOOT_PIN) == LOW) {
                    // Confirmed physical touch
                    user_present = true;
                    // Wait for release
                    while (digitalRead(BUTTON_BOOT_PIN) == LOW) {
                        delay(10);
                    }
                    break;
                }
            }
            delay(5);
        }

        if (user_present) {
            set_state(LedState::SUCCESS_GREEN);
            delay(250); // Feedback flash
        } else {
            set_state(LedState::ERROR_RED);
            delay(1000); // Display red on timeout/failure
        }

        // Return to standby state (Solid Green)
        set_state(LedState::STANDBY_GREEN);
        return user_present;
    }

    /**
     * @brief Air-Gapped Master Factory Wipe: 20-Second Hardware BOOT-Hold Check
     * 
     * Must be called at the very beginning of setup().
     * If GPIO 0 is held continuously for 20.0 seconds upon power-up:
     *   - Phase 1 (0..7s): Solid Yellow
     *   - Phase 2 (7..14s): Solid Warning Red
     *   - Phase 3 (14..20s): Rapid Flashing White (Brightness 150)
     *   - 20.0s: Executes wipe_cb(), flashes green 5 times, and halts.
     * Releasing the button at any moment prior to 20s aborts immediately.
     */
    bool check_power_on_wipe(void (*wipe_cb)()) {
        pinMode(BUTTON_BOOT_PIN, INPUT_PULLUP);
        if (digitalRead(BUTTON_BOOT_PIN) != LOW) {
            return false; // Button not pressed, boot normally immediately
        }

        uint32_t hold_start = millis();
        const uint32_t TOTAL_WIPE_TIME_MS = 20000;

        while (digitalRead(BUTTON_BOOT_PIN) == LOW) {
            uint32_t elapsed = millis() - hold_start;
            if (elapsed >= TOTAL_WIPE_TIME_MS) {
                // 20 Seconds reached! Execute master wipe
                if (wipe_cb) wipe_cb();

                // Flash confirmation green 5 times
                for (int i = 0; i < 5; i++) {
                    set_rgb_explicit(0, 255, 0, 150);
                    delay(100);
                    set_rgb_explicit(0, 0, 0, 0);
                    delay(100);
                }
                set_state(LedState::STANDBY_GREEN);
                return true;
            }

            if (elapsed < 7000) {
                // Phase 1 (0..7s): Solid Yellow Warning
                set_rgb_explicit(255, 180, 0, 60);
            } else if (elapsed < 14000) {
                // Phase 2 (7..14s): Solid Critical Red
                set_rgb_explicit(255, 0, 0, 100);
            } else {
                // Phase 3 (14..20s): Rapid Flashing White Countdown Strobe
                bool strobe = (elapsed / 60) % 2 == 0;
                set_rgb_explicit(255, 255, 255, strobe ? 150 : 0);
            }
            delay(10);
        }

        // Released before 20 seconds: abort cleanly
        set_state(LedState::STANDBY_GREEN);
        return false;
    }
};

/**
 * @brief Global singleton instance of PeripheralManager
 */
static inline PeripheralManager& get_peripherals() {
    static PeripheralManager instance;
    return instance;
}

} // namespace Peripherals
} // namespace OpenKey
