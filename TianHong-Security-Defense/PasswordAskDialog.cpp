#include "PasswordAskDialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>

ElaPasswordDialog::ElaPasswordDialog(const QString& archiveName, QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle("需要密码");
    setFixedSize(380, 190);

    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(20, 20, 20, 20);
    mainLayout->setSpacing(15);

    auto* label = new ElaText(QString("“%1” 已加密，请输入密码：").arg(archiveName), this);
    label->setWordWrap(true);
    mainLayout->addWidget(label);

    m_passwordEdit = new ElaLineEdit(this);
    m_passwordEdit->setEchoMode(ElaLineEdit::Password);
    m_passwordEdit->setPlaceholderText("密码");
    mainLayout->addWidget(m_passwordEdit);

    auto* btnLayout = new QHBoxLayout();
    btnLayout->addStretch();

    auto* skipBtn = new ElaPushButton("跳过", this);
    connect(skipBtn, &ElaPushButton::clicked, this, [this]() {
        m_passwordEdit->clear();
        reject();   // 返回空密码
        });
    btnLayout->addWidget(skipBtn);

    auto* okBtn = new ElaPushButton("确定", this);
    okBtn->setDefault(true);
    connect(okBtn, &ElaPushButton::clicked, this, &QDialog::accept);
    btnLayout->addWidget(okBtn);

    mainLayout->addLayout(btnLayout);
}

QString ElaPasswordDialog::password() const {
    return m_passwordEdit->text();
}