#include "BasePage.h"
#include "PublicIncluding.h"

BasePage::BasePage(QWidget* parent)
    : ElaScrollPage(parent)
{
}

BasePage::~BasePage()
{
}

void BasePage::createCustomWidget(QString desText)
{
    // 顶部元素
    QWidget* customWidget = new QWidget(this);

    ElaText* descText = new ElaText(this);
    descText->setText(desText);
    descText->setTextPixelSize(13);

    QVBoxLayout* topLayout = new QVBoxLayout(customWidget);
    topLayout->setContentsMargins(0, 0, 0, 0);
    topLayout->addWidget(descText);
    topLayout->addSpacing(20);

    setCustomWidget(customWidget);
}