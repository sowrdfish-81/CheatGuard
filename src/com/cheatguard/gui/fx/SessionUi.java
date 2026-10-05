package com.cheatguard.gui.fx;

import com.cheatguard.core.ExamSession;
import com.cheatguard.core.Violation;

/**
 * The bridge between the session controller ({@code Main}) and the JavaFX
 * interface. Implementations must hop to the FX thread where needed; the
 * controller calls these from worker threads as well as the FX thread.
 */
public interface SessionUi {

    /** The monitor screen in its "arming" state (helper handshake running). */
    void showStarting(ExamSession session);

    /** The monitor screen live (locks verified, watchdog running). */
    void showActive(ExamSession session);

    /**
     * One audit row for the live log. Called from any thread; implementations
     * must forward to the FX thread and may drop startup-window rows themselves.
     */
    void onViolation(Violation violation);

    /** The lockdown could not be armed; nothing was left changed. */
    void showStartFailure(String detail);

    /** The session sealed successfully; summary text is prebuilt by the controller. */
    void showSessionComplete(String summary);

    /** Windows did not confirm the network restore - show the recovery guidance. */
    void showRestoreWarning();

    /** Sealing the log failed; the session stays open for a retry. */
    void showSealError(String message);

    /** An exit-path refusal or note (wrong password, action in progress...). */
    void showExitMessage(String message);

    /** The process may close now. */
    void allowClose();

    /** Return to the home card (failed start). */
    void showHome();
}
