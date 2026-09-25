package com.cheatguard.security;

import com.cheatguard.core.AppLog;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;

/**
 * Keeps the active plaintext log open and locks only a tiny guard range.
 *
 * Why not lock the whole file?
 * On Windows a whole-file lock also blocks this application's own append
 * writer when it opens a second handle, producing:
 * "The process cannot access the file because another process has locked a portion of the file".
 *
 * Locking byte 0 keeps an OS-level guard while allowing append writes after
 * the existing content. The open RandomAccessFile handle also remains alive
 * for the full exam session and is released before sealing the vault.
 */
public class FileLockManager {
    private RandomAccessFile raf;
    private FileChannel channel;
    private FileLock lock;

    public synchronized boolean lockFile(File file) {
        releaseLock();
        try {
            raf = new RandomAccessFile(file, "rw");
            channel = raf.getChannel();
            // Guard only the first byte instead of the entire file.
            lock = channel.lock(0L, 1L, false);
            return true;
        } catch (IOException | RuntimeException e) {
            AppLog.warn("Could not protect active log: " + e.getMessage());
            releaseLock();
            return false;
        }
    }

    public synchronized void releaseLock() {
        try {
            if (lock != null && lock.isValid()) lock.release();
        } catch (IOException ignored) {
        } finally {
            lock = null;
        }
        try {
            if (channel != null && channel.isOpen()) channel.close();
        } catch (IOException ignored) {
        } finally {
            channel = null;
        }
        try {
            if (raf != null) raf.close();
        } catch (IOException ignored) {
        } finally {
            raf = null;
        }
    }
}
