package com.cheatguard.gui.fx;

import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.scene.text.Font;
import javafx.stage.Modality;
import javafx.stage.Stage;

import java.util.Optional;

/**
 * Styled dialogs for the JavaFX interface - the replacements for the JOptionPane
 * flows the Swing build used: messages, a yes-no confirmation and the
 * administrator password prompt with a reveal toggle.
 */
public final class FxDialogs {

    public enum Kind { PLAIN, INFO, WARN, ERROR }

    /** Show a modal message dialog and block until dismissed. */
    public static void message(Stage owner, String title, String header, String body, Kind kind) {
        Dialog<Void> d = baseDialog(owner, title, header, kind);
        d.getDialogPane().setContent(body(body));
        d.getDialogPane().getButtonTypes().add(ButtonType.OK);
        d.showAndWait();
    }

    /** Two-button confirmation; true only when the user accepted. */
    public static boolean confirm(Stage owner, String title, String header, String body, Kind kind) {
        Dialog<Boolean> d = baseDialog(owner, title, header, kind);
        d.getDialogPane().setContent(body(body));
        d.getDialogPane().getButtonTypes().addAll(ButtonType.YES, ButtonType.NO);
        d.setResultConverter(t -> t == ButtonType.YES);
        return d.showAndWait().orElse(false);
    }

    /**
     * Administrator password prompt with a reveal toggle. Returns the entered
     * characters, or null when cancelled. The caller owns wiping the array.
     */
    public static char[] password(Stage owner, String title) {
        Dialog<char[]> d = baseDialog(owner, title, "Administrator password", Kind.PLAIN);
        d.getDialogPane().getButtonTypes().addAll(ButtonType.OK, ButtonType.CANCEL);

        // A hidden PasswordField and a visible-on-demand TextField share their text;
        // the reveal toggle switches which one is on screen.
        PasswordField secret = new PasswordField();
        secret.setPromptText("Password");
        TextField plain = new TextField();
        plain.setVisible(false);
        plain.setManaged(false);
        secret.textProperty().bindBidirectional(plain.textProperty());

        Button reveal = new Button("Show");
        reveal.getStyleClass().add("button-ghost");
        reveal.setOnAction(e -> {
            boolean showing = plain.isVisible();
            plain.setVisible(!showing);
            plain.setManaged(!showing);
            secret.setVisible(showing);
            secret.setManaged(showing);
            reveal.setText(showing ? "Show" : "Hide");
            (showing ? secret : plain).requestFocus();
            ((TextField) (showing ? secret : plain)).end();
        });

        StackPane stack = new StackPane(secret, plain);
        stack.setPadding(new Insets(4, 0, 2, 0));
        HBox row = new HBox(10, stack, reveal);
        row.setAlignment(Pos.CENTER_LEFT);

        VBox content = new VBox(6,
                new Label("Enter the administrator password to continue."), row);
        content.setPadding(new Insets(2, 0, 2, 0));
        d.getDialogPane().setContent(content);

        Platform.runLater(secret::requestFocus);
        d.setResultConverter(t -> t == ButtonType.OK ? secret.getText().toCharArray() : null);
        Optional<char[]> result = d.showAndWait();
        Platform.runLater(() -> {
            secret.setText("");
            plain.setText("");
        });
        return result.orElse(null);
    }

    private static Label body(String text) {
        Label l = new Label(text);
        l.setWrapText(true);
        l.getStyleClass().add("text-muted");
        l.setMaxWidth(460);
        return l;
    }

    private static <T> Dialog<T> baseDialog(Stage owner, String title, String header, Kind kind) {
        Dialog<T> d = new Dialog<>();
        if (owner != null) d.initOwner(owner);
        d.initModality(Modality.APPLICATION_MODAL);
        d.setTitle(title);
        Scene scene = d.getDialogPane().getScene();
        if (scene != null) {
            scene.getStylesheets().add(FxDialogs.class.getResource("/fx-theme.css").toExternalForm());
        }
        d.getDialogPane().getStylesheets().add(FxDialogs.class.getResource("/fx-theme.css").toExternalForm());

        Label h = new Label(header);
        h.getStyleClass().add("h-title");
        h.setFont(Font.font("Inter SemiBold", 19));
        String mark = switch (kind) {
            case ERROR -> "●  ";
            case WARN -> "▲  ";
            case INFO -> "✓  ";
            default -> "";
        };
        if (!mark.isEmpty()) {
            Label accent = new Label(mark);
            accent.setFont(Font.font("Inter SemiBold", 18));
            accent.getStyleClass().add(switch (kind) {
                case ERROR -> "text-danger";
                case WARN -> "text-warn";
                case INFO -> "text-accent";
                default -> "text-muted";
            });
            HBox head = new HBox(4, accent, h);
            head.setAlignment(Pos.CENTER_LEFT);
            d.getDialogPane().setHeader(head);
        } else {
            d.getDialogPane().setHeader(h);
        }
        d.getDialogPane().setMinWidth(520);
        d.getDialogPane().setPadding(new Insets(4));
        return d;
    }

    private FxDialogs() {
    }
}
