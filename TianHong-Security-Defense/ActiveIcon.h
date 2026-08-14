#pragma once
#include "PublicIncluding.h"

namespace ActiveIcon {

    enum class IndicatorState {
        Right,    // 对勾 ✓ - 绿色
        Warn,     // 感叹号 ! - 橙色
        Error,    // 叉号 ✗ - 红色
        Critical  // 红色背景感叹号
    };

    class StateIndicatorWidget : public QWidget
    {
        Q_OBJECT
            Q_PROPERTY(qreal pulseFactor READ pulseFactor WRITE setPulseFactor)
            Q_PROPERTY(qreal breathIntensity READ breathIntensity WRITE setBreathIntensity)
            Q_PROPERTY(qreal morphProgress READ morphProgress WRITE setMorphProgress)
            Q_PROPERTY(QColor currentColor READ currentColor WRITE setCurrentColor)
            Q_PROPERTY(qreal borderGlow READ borderGlow WRITE setBorderGlow)

    public:
        explicit StateIndicatorWidget(QWidget* parent = nullptr);
        QSize sizeHint() const override { return QSize(200, 200); }
        QSize minimumSizeHint() const override { return QSize(100, 100); }

        qreal pulseFactor() const { return m_pulseFactor; }
        void setPulseFactor(qreal factor);

        qreal breathIntensity() const { return m_breathIntensity; }
        void setBreathIntensity(qreal intensity);

        qreal morphProgress() const { return m_morphProgress; }
        void setMorphProgress(qreal progress);

        QColor currentColor() const { return m_currentColor; }
        void setCurrentColor(const QColor& color);

        qreal borderGlow() const { return m_borderGlow; }
        void setBorderGlow(qreal glow);

        void setState(IndicatorState newState, bool animated = true);

    protected:
        void paintEvent(QPaintEvent* event) override;

    private:
        void setupAnimations();
        void startIdleAnimations();
        void stopIdleAnimations();

        // 六边形相关函数
        QPolygonF createHexagon(const QRectF& rect, qreal scale = 1.0);
        void drawHexagonBorder(QPainter* painter, const QPolygonF& hexagon, const QColor& color);
        void drawHexagonGlow(QPainter* painter, const QPolygonF& hexagon, const QColor& color);

        // 内部图标绘制
        void drawIconWithPen(QPainter* painter, const QRectF& rect, IndicatorState state, const QColor& color);
        void drawMorphingIcon(QPainter* painter, const QRectF& rect, qreal morphValue, const QColor& color);

        QColor getStateColor(IndicatorState state) const;

    private:
        // 动画属性值
        qreal m_pulseFactor;
        qreal m_breathIntensity;
        qreal m_morphProgress;
        qreal m_borderGlow;
        QColor m_currentColor;

        IndicatorState m_currentState;
        IndicatorState m_targetState;

        // 动画对象
        QVariantAnimation* m_pulseAnim;
        QVariantAnimation* m_breathAnim;
        QVariantAnimation* m_morphAnim;
        QPropertyAnimation* m_colorAnim;
        QParallelAnimationGroup* m_idleGroup;

        bool m_isTransitioning;
    };

} // namespace ActiveIcon
