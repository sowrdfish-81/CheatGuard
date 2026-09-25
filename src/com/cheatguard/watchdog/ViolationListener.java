package com.cheatguard.watchdog;

import com.cheatguard.core.Violation;

/**
 * OOP Concept: INTERFACE (abstraction)
 * --------------------------------------
 * WatchdogEngine ke direct AlarmPlayer/ScreenLocker class chinte hobe na.
 * Eta shudhu jane je "kono violation hole, ekta onVoilation() call hobe".
 * Main.java run-time e ekta implementation (lambda) diye WatchdogEngine ke
 * bole dey exactly ki korte hobe (alarm baja, screen lock kora, etc).
 * Eta "loose coupling" - alada module gula ek-onner shathe tightly bound thake na.
 */
public interface ViolationListener {
    void onViolation(Violation violation);
}
