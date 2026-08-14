#pragma once
#include <QDialog>
#include "ElaLineEdit.h"
#include "ElaPushButton.h"
#include "ElaText.h"

class ElaPasswordDialog : public QDialog {
    Q_OBJECT
public:
    explicit ElaPasswordDialog(const QString& archiveName, QWidget* parent = nullptr);
    QString password() const;

private:
    ElaLineEdit* m_passwordEdit;
};