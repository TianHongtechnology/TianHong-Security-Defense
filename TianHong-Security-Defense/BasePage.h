#pragma once
#include <ElaScrollPage.h>

class QVBoxLayout;
class BasePage : public ElaScrollPage
{
    Q_OBJECT
public:
    explicit BasePage(QWidget* parent = nullptr);
    ~BasePage() override;

protected:
    void createCustomWidget(QString desText);
};