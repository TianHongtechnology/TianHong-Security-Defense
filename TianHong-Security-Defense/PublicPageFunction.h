#pragma once
#include "PublicIncluding.h"

void slideInOut(QWidget* widget, bool isIn = true) {
    if (!widget) return;

    // 创建并行动画组
    QParallelAnimationGroup* group = new QParallelAnimationGroup;

    // 位置动画
    QPropertyAnimation* posAnimation = new QPropertyAnimation(widget, "pos");
    posAnimation->setDuration(600);
    posAnimation->setEasingCurve(QEasingCurve::OutCubic);

    if (isIn) {
        // 滑入：从右侧淡入
        QPoint startPos = QPoint(widget->parentWidget() ? widget->parentWidget()->width() : widget->width(),
            widget->y());
        QPoint endPos = widget->pos();

        widget->move(startPos);
        widget->show();
        widget->raise();

        posAnimation->setStartValue(startPos);
        posAnimation->setEndValue(endPos);
    }
    else {
        widget->setWindowOpacity(1);

        // 滑出：向右侧淡出
        QPoint startPos = widget->pos();
        QPoint endPos = QPoint(widget->parentWidget() ? widget->parentWidget()->width() : widget->width(),
            widget->y());

        posAnimation->setStartValue(startPos);
        posAnimation->setEndValue(endPos);

        // 动画结束后隐藏
        QObject::connect(group, &QParallelAnimationGroup::finished, widget, [=]() {
            widget->hide();
            widget->move(startPos);
            });
    }

    group->addAnimation(posAnimation);
    group->start(QParallelAnimationGroup::DeleteWhenStopped);
}

void slideProgressInOut(QWidget* widget, bool isIn = true) {
    if (!widget) return;

    static QMap<QWidget*, QPoint> originalPositions; // 静态变量记录原始位置

    QWidget* parent = widget->parentWidget();
    if (!parent) return;

    // 找到所有在进度条下方的控件
    QList<QWidget*> widgetsBelow;
    QList<QWidget*> allWidgets = parent->findChildren<QWidget*>();

    for (QWidget* w : allWidgets) {
        if (w == widget || !w->isVisible() || w->parent() != parent)
            continue;
        if (w->y() > widget->y()) {
            widgetsBelow.append(w);
        }
    }

    // 滑动距离
    int slideDistance = 30;

    if (isIn) {
        // 第一次调用时记录原始位置
        for (QWidget* w : widgetsBelow) {
            if (!originalPositions.contains(w)) {
                originalPositions[w] = w->pos();
            }
        }

        // 下方控件向下滑动
        QParallelAnimationGroup* group = new QParallelAnimationGroup;

        for (QWidget* w : widgetsBelow) {
            QPropertyAnimation* anim = new QPropertyAnimation(w, "pos");
            anim->setDuration(600);
            anim->setEasingCurve(QEasingCurve::OutCubic);

            QPoint currentPos = w->pos();
            QPoint targetPos = QPoint(currentPos.x(), originalPositions[w].y() + slideDistance);

            anim->setStartValue(currentPos);
            anim->setEndValue(targetPos);
            group->addAnimation(anim);
        }

        // 使用原有的slideInOut显示进度条
        slideInOut(widget, true);

        group->start(QParallelAnimationGroup::DeleteWhenStopped);
    }
    else {
        // 下方控件向上滑动恢复
        QParallelAnimationGroup* group = new QParallelAnimationGroup;

        for (QWidget* w : widgetsBelow) {
            QPropertyAnimation* anim = new QPropertyAnimation(w, "pos");
            anim->setDuration(600);
            anim->setEasingCurve(QEasingCurve::OutCubic);

            QPoint currentPos = w->pos();
            QPoint targetPos = originalPositions.value(w, currentPos);

            anim->setStartValue(currentPos);
            anim->setEndValue(targetPos);
            group->addAnimation(anim);
        }

        // 使用原有的slideInOut隐藏进度条
        slideInOut(widget, false);

        group->start(QParallelAnimationGroup::DeleteWhenStopped);
    }
}