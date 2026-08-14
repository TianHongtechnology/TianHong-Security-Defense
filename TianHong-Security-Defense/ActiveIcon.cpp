#include "ActiveIcon.h"

namespace ActiveIcon {

    StateIndicatorWidget::StateIndicatorWidget(QWidget* parent)
        : QWidget(parent)
        , m_pulseFactor(1.0)
        , m_breathIntensity(0.7)
        , m_morphProgress(1.0)
        , m_borderGlow(0.5)
        , m_currentColor(Qt::green)
        , m_currentState(IndicatorState::Right)
        , m_targetState(IndicatorState::Right)
        , m_isTransitioning(false)
    {
        setMinimumSize(100, 100);
        setupAnimations();
        startIdleAnimations();
    }

    void StateIndicatorWidget::setupAnimations()
    {
        // 使用正弦波实现完美循环的脉冲和呼吸效果
        // 动画范围 0 → 2π，对应 sin 值 0 → 1 → 0 → -1 → 0，映射到需要的范围

        // 脉冲动画：sin 值从 0 到 2π，周期 2 秒
        m_pulseAnim = new QVariantAnimation(this);
        m_pulseAnim->setDuration(2000);
        m_pulseAnim->setStartValue(0.0);
        m_pulseAnim->setEndValue(2 * M_PI);
        m_pulseAnim->setEasingCurve(QEasingCurve::Linear);  // 线性变化角度
        m_pulseAnim->setLoopCount(-1);

        // 呼吸动画：同样周期 2.5 秒，可独立周期
        m_breathAnim = new QVariantAnimation(this);
        m_breathAnim->setDuration(2500);
        m_breathAnim->setStartValue(0.0);
        m_breathAnim->setEndValue(2 * M_PI);
        m_breathAnim->setEasingCurve(QEasingCurve::Linear);
        m_breathAnim->setLoopCount(-1);

        // 形态切换动画（保持不变）
        m_morphAnim = new QVariantAnimation(this);
        m_morphAnim->setDuration(400);
        m_morphAnim->setEasingCurve(QEasingCurve::InOutCubic);

        // 颜色切换动画（保持不变）
        m_colorAnim = new QPropertyAnimation(this, "currentColor");
        m_colorAnim->setDuration(400);
        m_colorAnim->setEasingCurve(QEasingCurve::InOutQuad);

        // 脉冲：0.98 ↔ 1.02 (±2%)，更 subtle
        connect(m_pulseAnim, &QVariantAnimation::valueChanged, this, [this](const QVariant& val) {
            qreal angle = val.toReal();
            qreal sinVal = qSin(angle);
            qreal factor = 0.98 + (sinVal + 1.0) / 2.0 * 0.04;  // 映射到 0.98~1.02
            setPulseFactor(factor);
            });

        // 呼吸：0.75 ↔ 0.95 (变化20%)，更柔和
        connect(m_breathAnim, &QVariantAnimation::valueChanged, this, [this](const QVariant& val) {
            qreal angle = val.toReal();
            qreal sinVal = qSin(angle);
            qreal intensity = 0.75 + (sinVal + 1.0) / 2.0 * 0.20;  // 映射到 0.75~0.95
            setBreathIntensity(intensity);
            setBorderGlow(0.3 + intensity * 0.4);  // 光晕变化也更平缓
            });

        connect(m_morphAnim, &QVariantAnimation::valueChanged, this, [this](const QVariant& val) {
            setMorphProgress(val.toReal());
            });
        connect(m_colorAnim, &QPropertyAnimation::valueChanged, this, [this](const QVariant& val) {
            setCurrentColor(val.value<QColor>());
            });
        connect(m_morphAnim, &QVariantAnimation::finished, this, [this]() {
            m_isTransitioning = false;
            m_currentState = m_targetState;
            m_morphProgress = 1.0;
            update();
            });

        m_idleGroup = new QParallelAnimationGroup(this);
        m_idleGroup->addAnimation(m_pulseAnim);
        m_idleGroup->addAnimation(m_breathAnim);
        m_idleGroup->setLoopCount(-1);
    }

    void StateIndicatorWidget::startIdleAnimations()
    {
        if (m_idleGroup->state() != QAbstractAnimation::Running) {
            m_idleGroup->start();
        }
    }

    void StateIndicatorWidget::stopIdleAnimations()
    {
        if (m_idleGroup->state() == QAbstractAnimation::Running) {
            m_idleGroup->stop();
        }
    }

    void StateIndicatorWidget::setState(IndicatorState newState, bool animated)
    {
        if (newState == m_currentState && !m_isTransitioning) {
            return;
        }

        m_targetState = newState;

        if (animated) {
            m_isTransitioning = true;
            stopIdleAnimations();
            m_morphProgress = 0.0;
            m_morphAnim->setStartValue(0.0);
            m_morphAnim->setEndValue(1.0);
            m_morphAnim->start();
            m_colorAnim->setStartValue(m_currentColor);
            m_colorAnim->setEndValue(getStateColor(m_targetState));
            m_colorAnim->start();
        }
        else {
            m_currentState = newState;
            m_targetState = newState;
            m_currentColor = getStateColor(newState);
            m_morphProgress = 1.0;
            update();
        }
    }

    QPolygonF StateIndicatorWidget::createHexagon(const QRectF& rect, qreal scale)
    {
        QPolygonF hexagon;
        QPointF center = rect.center();
        qreal radius = qMin(rect.width(), rect.height()) / 2 * scale;

        for (int i = 0; i < 6; ++i) {
            qreal angle = i * 60.0 - 30.0;  // -30度让六边形有一个角朝上
            qreal rad = qDegreesToRadians(angle);
            qreal x = center.x() + radius * qCos(rad);
            qreal y = center.y() + radius * qSin(rad);
            hexagon << QPointF(x, y);
        }
        return hexagon;
    }

    void StateIndicatorWidget::drawHexagonBorder(QPainter* painter, const QPolygonF& hexagon, const QColor& color)
    {
        painter->save();
        painter->setBrush(Qt::NoBrush);

        // 外边框（较粗）
        QPen borderPen(color);
        borderPen.setWidthF(qMin(width(), height()) * 0.08);
        borderPen.setCapStyle(Qt::RoundCap);
        borderPen.setJoinStyle(Qt::RoundJoin);
        painter->setPen(borderPen);
        painter->drawPolygon(hexagon);

        // 内边框（较细，增加层次感）
        QPolygonF innerHexagon;
        QPointF center = hexagon.boundingRect().center();
        for (const QPointF& point : hexagon) {
            QPointF dir = point - center;
            innerHexagon << center + dir * 0.75;
        }
        QPen innerPen(color.lighter(130));
        innerPen.setWidthF(qMin(width(), height()) * 0.03);
        innerPen.setCapStyle(Qt::RoundCap);
        innerPen.setJoinStyle(Qt::RoundJoin);
        painter->setPen(innerPen);
        painter->drawPolygon(innerHexagon);

        painter->restore();
    }

    void StateIndicatorWidget::drawHexagonGlow(QPainter* painter, const QPolygonF& hexagon, const QColor& color)
    {
        painter->save();
        painter->setPen(Qt::NoPen);

        // 光晕效果：多层渐变
        QRadialGradient glowGradient(hexagon.boundingRect().center(),
            qMin(width(), height()) * 0.5);
        QColor glowColor = color;
        glowColor.setAlpha(40 * m_borderGlow);
        glowGradient.setColorAt(0, glowColor);
        glowColor.setAlpha(15 * m_borderGlow);
        glowGradient.setColorAt(0.5, glowColor);
        glowColor.setAlpha(0);
        glowGradient.setColorAt(1, glowColor);

        painter->setBrush(glowGradient);
        painter->drawPolygon(hexagon);

        painter->restore();
    }

    void StateIndicatorWidget::drawIconWithPen(QPainter* painter, const QRectF& rect,
        IndicatorState state, const QColor& color)
    {
        painter->save();

        qreal w = rect.width();
        qreal h = rect.height();
        qreal strokeWidth = qMin(w, h) * 0.12;  // 稍微加粗一点更醒目

        QPen pen(color);
        pen.setWidthF(strokeWidth);
        pen.setCapStyle(Qt::RoundCap);
        pen.setJoinStyle(Qt::RoundJoin);

        switch (state) {
        case IndicatorState::Right: {
            // 重新设计的对勾路径：起点(0.25w, 0.55h) → 中点(0.45w, 0.75h) → 终点(0.75w, 0.35h)
            QPointF start(rect.left() + w * 0.25, rect.top() + h * 0.55);
            QPointF mid(rect.left() + w * 0.45, rect.top() + h * 0.75);
            QPointF end(rect.left() + w * 0.75, rect.top() + h * 0.35);

            QPainterPath path;
            path.moveTo(start);
            path.lineTo(mid);
            path.lineTo(end);

            // 使用 QPainterPathStroker 生成填充路径，确保圆角且粗细均匀
            QPainterPathStroker stroker;
            stroker.setWidth(strokeWidth);
            stroker.setCapStyle(Qt::RoundCap);
            stroker.setJoinStyle(Qt::RoundJoin);
            QPainterPath strokePath = stroker.createStroke(path);

            painter->setBrush(color);
            painter->setPen(Qt::NoPen);
            painter->drawPath(strokePath);
            break;
        }
        case IndicatorState::Warn: {
            // 无外框三角，仅保留橙色感叹号
            painter->setPen(pen);
            painter->setBrush(Qt::NoBrush);
            QPointF exTop(rect.center().x(), rect.top() + h * 0.32);
            QPointF exBottom(rect.center().x(), rect.top() + h * 0.68);
            painter->drawLine(exTop, exBottom);

            qreal dotSize = qMin(w, h) * 0.12;
            QRectF dotRect(rect.center().x() - dotSize / 2.0,
                rect.bottom() - h * 0.18 - dotSize / 2.0,
                dotSize,
                dotSize);
            painter->setBrush(color);
            painter->setPen(Qt::NoPen);
            painter->drawEllipse(dotRect);
            break;
        }
        case IndicatorState::Error: {
            // 叉号保持不变
            QPointF topLeft(rect.left() + w * 0.3, rect.top() + h * 0.3);
            QPointF bottomRight(rect.right() - w * 0.3, rect.bottom() - h * 0.3);
            QPointF topRight(rect.right() - w * 0.3, rect.top() + h * 0.3);
            QPointF bottomLeft(rect.left() + w * 0.3, rect.bottom() - h * 0.3);
            painter->setPen(pen);
            painter->setBrush(Qt::NoBrush);
            painter->drawLine(topLeft, bottomRight);
            painter->drawLine(topRight, bottomLeft);
            break;
        }
        case IndicatorState::Critical: {
            // 无外框三角，仅保留红色感叹号
            painter->setPen(pen);
            painter->setBrush(Qt::NoBrush);

            QPointF exTop(rect.center().x(), rect.top() + h * 0.32);
            QPointF exBottom(rect.center().x(), rect.top() + h * 0.68);
            painter->drawLine(exTop, exBottom);

            qreal dotSize = qMin(w, h) * 0.12;
            QRectF dotRect(rect.center().x() - dotSize / 2.0,
                rect.bottom() - h * 0.18 - dotSize / 2.0,
                dotSize,
                dotSize);
            painter->setBrush(color);
            painter->setPen(Qt::NoPen);
            painter->drawEllipse(dotRect);
            break;
        }
        }

        painter->restore();
    }

    void StateIndicatorWidget::drawMorphingIcon(QPainter* painter, const QRectF& rect,
        qreal morphValue, const QColor& color)
    {
        painter->save();

        // 先绘制起始图标（淡出）
        painter->setOpacity(1.0 - morphValue);
        drawIconWithPen(painter, rect, m_currentState, color);

        // 再绘制目标图标（淡入）
        painter->setOpacity(morphValue);
        drawIconWithPen(painter, rect, m_targetState, color);

        painter->restore();
    }

    void StateIndicatorWidget::paintEvent(QPaintEvent* event)
    {
        Q_UNUSED(event);
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing, true);
        painter.setRenderHint(QPainter::SmoothPixmapTransform, true);

        // 计算绘制区域（留出边距）
        QRectF widgetRect = rect();
        qreal margin = qMin(width(), height()) * 0.08;
        QRectF drawRect = widgetRect.adjusted(margin, margin, -margin, -margin);

        // 应用脉冲缩放
        qreal scale = m_pulseFactor;

        // 创建六边形（带缩放）
        QPolygonF hexagon = createHexagon(drawRect, scale);

        // 根据呼吸强度调整颜色亮度
        QColor drawColor = m_currentColor;
        int lightness = 120 + int(m_breathIntensity * 100);
        drawColor = QColor::fromHsv(drawColor.hue(),
            drawColor.saturation(),
            qBound(100, lightness, 220));

        // 绘制背景光晕
        drawHexagonGlow(&painter, hexagon, drawColor);

        // 绘制六边形边框
        drawHexagonBorder(&painter, hexagon, drawColor);

        // 计算内部图标区域（六边形内部）
        QRectF iconRect = hexagon.boundingRect();
        iconRect.adjust(iconRect.width() * 0.2, iconRect.height() * 0.2,
            -iconRect.width() * 0.2, -iconRect.height() * 0.2);

        // 绘制内部图标
        if (m_isTransitioning) {
            drawMorphingIcon(&painter, iconRect, m_morphProgress, drawColor);
        }
        else {
            drawIconWithPen(&painter, iconRect, m_currentState, drawColor);
        }

        // 恢复空闲动画
        if (!m_isTransitioning && m_idleGroup->state() != QAbstractAnimation::Running) {
            startIdleAnimations();
        }
    }

    QColor StateIndicatorWidget::getStateColor(IndicatorState state) const
    {
        switch (state) {
        case IndicatorState::Right:
            return QColor(0, 200, 100);      // 卡巴斯基绿
        case IndicatorState::Warn:
            return QColor(255, 160, 0);       // 橙色
        case IndicatorState::Error:
            return QColor(255, 80, 60);       // 红色
        case IndicatorState::Critical:
            return QColor(220, 40, 40);       // 深红色背景
        default:
            return Qt::green;
        }
    }

    void StateIndicatorWidget::setPulseFactor(qreal factor)
    {
        m_pulseFactor = factor;
        update();
    }

    void StateIndicatorWidget::setBreathIntensity(qreal intensity)
    {
        m_breathIntensity = intensity;
        update();
    }

    void StateIndicatorWidget::setMorphProgress(qreal progress)
    {
        m_morphProgress = progress;
        update();
    }

    void StateIndicatorWidget::setCurrentColor(const QColor& color)
    {
        m_currentColor = color;
        update();
    }

    void StateIndicatorWidget::setBorderGlow(qreal glow)
    {
        m_borderGlow = glow;
        update();
    }

} // namespace ActiveIcon