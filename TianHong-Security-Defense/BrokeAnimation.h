#pragma once

#include <QDialog>
#include <QPropertyAnimation>
#include <QSequentialAnimationGroup>
#include <QFileIconProvider>
#include <QPixmap>
#include <QPainter>
#include <QPainterPath>
#include <QLabel>
#include <QTimer>
#include <QThread>
#include <QApplication>
#include <QRandomGenerator>
#include <QtMath>
#include <QVector>
#include <QStyle>

// ============ 自定义绘制对话框 ============
class FileBreakDialog : public QDialog {
	Q_OBJECT
		Q_PROPERTY(int cutOffset READ cutOffset WRITE setCutOffset)
		Q_PROPERTY(int phaseProgress READ phaseProgress WRITE setPhaseProgress)

public:
	explicit FileBreakDialog(const QPixmap& iconPixmap, QWidget* parent = nullptr)
		: QDialog(parent)
		, m_iconPixmap(iconPixmap)
		, m_cutOffset(0)
		, m_phaseProgress(0)
	{
		// 透明无边框设置
		setWindowFlags(Qt::FramelessWindowHint | Qt::Tool | Qt::WindowStaysOnTopHint);
		setAttribute(Qt::WA_TranslucentBackground, true);
		setAttribute(Qt::WA_DeleteOnClose, true);
		setModal(false);

		// 对话框大小略大于图标，给动画留空间
		const int dialogSize = qMax(iconPixmap.width(), iconPixmap.height()) + 200;
		setFixedSize(dialogSize, dialogSize);

		// 居中图标区域
		m_iconRect = QRect((width() - iconPixmap.width()) / 2,
			(height() - iconPixmap.height()) / 2,
			iconPixmap.width(),
			iconPixmap.height());

		// 预生成斩杀分割的两部分（沿左上到左下的曲线分割）
		generateCutParts();

		// 预生成不规则碎片（第二阶段用）
		generateIrregularFragments();
	}

	void startAnimation()
	{
		// 阶段 1：斩杀切割分离（600ms）
		auto* cutAnim = new QPropertyAnimation(this, "cutOffset");
		cutAnim->setDuration(600);
		cutAnim->setStartValue(0);
		cutAnim->setEndValue(60); // 分离距离
		cutAnim->setEasingCurve(QEasingCurve::OutCubic);

		// 阶段 2：破碎飞散（1500ms）
		auto* phaseAnim = new QPropertyAnimation(this, "phaseProgress");
		phaseAnim->setDuration(1500);
		phaseAnim->setStartValue(0);
		phaseAnim->setEndValue(100);

		auto* group = new QSequentialAnimationGroup(this);
		group->addAnimation(cutAnim);
		group->addAnimation(phaseAnim);

		connect(group, &QSequentialAnimationGroup::finished, this, &QDialog::close);
		group->start(QAbstractAnimation::DeleteWhenStopped);
	}

protected:
	void paintEvent(QPaintEvent*) override
	{
		QPainter painter(this);
		painter.setRenderHint(QPainter::Antialiasing, true);
		painter.setRenderHint(QPainter::SmoothPixmapTransform, true);

		if (m_phaseProgress == 0) {
			// 阶段 1：绘制斩杀切割效果（两部分分离 + 刀光）
			drawCutPhase(painter);
		}
		else {
			// 阶段 2：绘制不规则碎片飞散
			drawFragmentPhase(painter);
		}
	}

	// 属性访问器（用于动画）
	int cutOffset() const { return m_cutOffset; }
	void setCutOffset(int offset) { m_cutOffset = offset; update(); }
	int phaseProgress() const { return m_phaseProgress; }
	void setPhaseProgress(int progress) { m_phaseProgress = progress; update(); }

private:
	// ========== 斩杀分割部分 ==========
	void generateCutParts()
	{
		const QPointF topLeft(0, 0);
		const QPointF bottomLeft(0, m_iconPixmap.height());

		// 控制点右移，使被斩下的部分更大
		const QPointF ctrl1(m_iconPixmap.width() * 0.55, m_iconPixmap.height() * 0.20);
		const QPointF ctrl2(m_iconPixmap.width() * 0.50, m_iconPixmap.height() * 0.80);

		// 右侧部分路径（主体）
		QPainterPath cutPath;
		cutPath.moveTo(topLeft);
		cutPath.cubicTo(ctrl1, ctrl2, bottomLeft);
		cutPath.lineTo(bottomLeft + QPointF(m_iconPixmap.width(), 0));
		cutPath.lineTo(topLeft + QPointF(m_iconPixmap.width(), 0));
		cutPath.closeSubpath();

		// 左侧部分路径（被斩下的小块）
		QPainterPath leftPath;
		leftPath.moveTo(topLeft);
		leftPath.cubicTo(ctrl1, ctrl2, bottomLeft);
		leftPath.lineTo(bottomLeft);
		leftPath.lineTo(topLeft);
		leftPath.closeSubpath();

		m_leftPart = extractPixmapByPath(leftPath);
		m_rightPart = extractPixmapByPath(cutPath);

		m_leftStartPos = m_iconRect.topLeft();
		m_rightStartPos = m_iconRect.topLeft();
	}

	QPixmap extractPixmapByPath(const QPainterPath& path) const
	{
		QPixmap part(m_iconPixmap.size());
		part.fill(Qt::transparent);
		QPainter p(&part);
		p.setClipPath(path);
		p.drawPixmap(0, 0, m_iconPixmap);
		return part;
	}

	void drawCutPhase(QPainter& painter) const
	{
		const qreal offset = m_cutOffset;
		const QPointF leftOffset(-offset * 0.8, -offset * 0.5);
		const QPointF rightOffset(offset * 0.6, offset * 0.8);

		painter.save();
		painter.setOpacity(1.0);

		// 绘制右侧部分（主体）
		painter.drawPixmap(m_rightStartPos + rightOffset, m_rightPart);

		// 绘制左侧部分（被斩开的小块）
		painter.drawPixmap(m_leftStartPos + leftOffset, m_leftPart);
		painter.restore();

		// 切割曲线的控制点（与 generateCutParts 中保持一致）
		const QPointF topLeft(0, 0);
		const QPointF bottomLeft(0, m_iconPixmap.height());
		const QPointF ctrl1(m_iconPixmap.width() * 0.55, m_iconPixmap.height() * 0.20);
		const QPointF ctrl2(m_iconPixmap.width() * 0.50, m_iconPixmap.height() * 0.80);

		// 构建切割曲线（图标内部坐标）
		QPainterPath slashPath;
		slashPath.moveTo(topLeft);
		slashPath.cubicTo(ctrl1, ctrl2, bottomLeft);

		// 将曲线平移到图标在对话框中的实际位置
		slashPath.translate(m_iconRect.topLeft());

		// 刀光主体
		painter.setPen(QPen(QColor(255, 255, 200, 180), 4));
		painter.drawPath(slashPath);

		// 光晕效果
		painter.setPen(QPen(QColor(255, 200, 100, 100), 10));
		painter.drawPath(slashPath);

		// 火花粒子点缀（沿切割曲线分布）
		painter.setBrush(QColor(255, 180, 50, 200));
		painter.setPen(Qt::NoPen);
		for (int i = 0; i < 6; ++i) {
			qreal t = m_cutOffset / 60.0 + i * 0.1;
			if (t > 1.0) t = 1.0;
			const QPointF pt = slashPath.pointAtPercent(t);
			const qreal radius = 2.0 + m_cutOffset * 0.05;
			painter.drawEllipse(pt, radius, radius);
		}
	}

	// ========== 不规则碎片部分 ==========
	struct IrregularFragment {
		QPainterPath shape; // 不规则多边形形状（相对于图标左上角）
		QPointF startPos; // 初始位置（图标内的绝对坐标）
		QPointF velocity; // 飞散方向向量
		qreal rotationSpeed; // 旋转速度（度/进度百分比）
		qreal initialRotation; // 初始旋转角度
	};

	void generateIrregularFragments()
	{
		constexpr int kFragmentCount = 32;
		const int w = m_iconPixmap.width();
		const int h = m_iconPixmap.height();
		const QPointF center = m_iconRect.center();

		m_fragments.reserve(kFragmentCount);

		for (int i = 0; i < kFragmentCount; ++i) {
			IrregularFragment frag;

			// 随机生成 3~5 个顶点的不规则形状
			const int vertexCount = QRandomGenerator::global()->bounded(3, 6);
			QPolygonF polygon;

			// 随机中心点
			const qreal fragCenterX = QRandomGenerator::global()->bounded(w);
			const qreal fragCenterY = QRandomGenerator::global()->bounded(h);
			const qreal maxRadius = QRandomGenerator::global()->bounded(15, 35);

			for (int v = 0; v < vertexCount; ++v) {
				const qreal angleStep = (2 * M_PI * v) / vertexCount;
				const qreal angleOffset = (QRandomGenerator::global()->generateDouble() - 0.5) * (M_PI / 3.0);
				const qreal angle = angleStep + angleOffset;

				const qreal radius = maxRadius * (0.6 + QRandomGenerator::global()->generateDouble() * 0.4);
				qreal x = fragCenterX + radius * qCos(angle);
				qreal y = fragCenterY + radius * qSin(angle);

				// 边界裁剪，确保在图标范围内
				x = qBound(0.0, x, static_cast<qreal>(w));
				y = qBound(0.0, y, static_cast<qreal>(h));
				polygon << QPointF(x, y);
			}

			// 确保多边形至少是三角形
			if (polygon.size() < 3)
				continue;

			// 将多边形转为 QPainterPath
			frag.shape.addPolygon(polygon);

			// 计算碎片实际在图标内的位置（用于绘制）
			const QRectF bounds = frag.shape.boundingRect();
			frag.startPos = m_iconRect.topLeft() + bounds.topLeft();

			// 速度方向：从图标中心向外 + 随机扰动
			const QPointF fragRealCenter = m_iconRect.topLeft() + QPointF(fragCenterX, fragCenterY);
			QPointF dir = fragRealCenter - center;
			const qreal len = qSqrt(dir.x() * dir.x() + dir.y() * dir.y());
			if (len < 0.01)
				dir = QPointF(1.0, 0.0);
			else
				dir /= len;

			// 添加随机角度偏移（最大约 ±60 度）
			const qreal angleVariation = (QRandomGenerator::global()->generateDouble() - 0.5) * 1.2;
			const qreal cosA = qCos(angleVariation);
			const qreal sinA = qSin(angleVariation);
			frag.velocity = QPointF(dir.x() * cosA - dir.y() * sinA,
				dir.y() * cosA + dir.x() * sinA);

			// 旋转速度（度/百分比）和初始角度
			frag.rotationSpeed = QRandomGenerator::global()->bounded(180, 540) / 100.0;
			frag.initialRotation = QRandomGenerator::global()->bounded(360.0);

			m_fragments.append(frag);
		}
	}

	void drawFragmentPhase(QPainter& painter) const
	{
		qreal progress = m_phaseProgress / 100.0; // 0 → 1
		if (progress > 1.0)
			progress = 1.0;

		// 绘制各个碎片
		for (const IrregularFragment& frag : m_fragments) {
			qreal alpha = 1.0 - progress * 1.2;
			if (alpha < 0.0)
				alpha = 0.0;

			painter.save();
			painter.setOpacity(alpha);

			// 位移：随进度增大向外飞散（最远 180 像素）
			const QPointF offset = frag.velocity * progress * 180.0;
			const QPointF pos = frag.startPos + offset;

			// 旋转变换
			const qreal rotation = frag.initialRotation + frag.rotationSpeed * progress * 100.0;
			const QRectF bounds = frag.shape.boundingRect();
			const QPointF pivot = pos + QPointF(bounds.width() / 2.0, bounds.height() / 2.0);
			painter.translate(pivot);
			painter.rotate(rotation);
			painter.translate(-pivot);

			// 设置裁剪路径并绘制原图标对应区域
			QPainterPath worldPath = frag.shape;
			worldPath.translate(m_iconRect.topLeft());
			painter.setClipPath(worldPath);
			painter.drawPixmap(m_iconRect.topLeft(), m_iconPixmap);

			painter.restore();
		}

		// 碎片拖尾粒子效果
		if (progress > 0.2) {
			painter.setPen(Qt::NoPen);
			painter.setBrush(QColor(255, 180, 80, 60));
			for (int i = 0; i < 20; ++i) {
				const int seed = (i * 131) % m_fragments.size();
				const IrregularFragment& f = m_fragments[seed];
				const qreal extra = progress * 0.8;
				const QPointF trailPos = f.startPos + f.velocity * (progress * 180.0 + 10.0);
				const qreal radius = 2.0 + extra * 3.0;
				painter.drawEllipse(trailPos, radius, radius);
			}
		}
	}

	// ───── 成员变量 ─────
	QPixmap m_iconPixmap;
	QRect m_iconRect;

	// 斩杀分割相关
	QPixmap m_leftPart;
	QPixmap m_rightPart;
	QPointF m_leftStartPos;
	QPointF m_rightStartPos;
	int m_cutOffset = 0; // 0 ~ 60
	int m_phaseProgress = 0; // 0 ~ 100

	// 不规则碎片列表
	QVector<IrregularFragment> m_fragments;
};

// ============ 线程安全的公共接口 ============
inline void showFileIconBreakAnimationAsync(const QString& filePath, QWidget* parent = nullptr)
{
	if (QThread::currentThread() != QApplication::instance()->thread()) {
		QMetaObject::invokeMethod(QApplication::instance(), [filePath, parent]() {
		showFileIconBreakAnimationAsync(filePath, parent);
			}, Qt::QueuedConnection);
		return;
	}

	QFileIconProvider iconProvider;
	QIcon icon = iconProvider.icon(QFileInfo(filePath));
	if (icon.isNull())
		icon = qApp->style()->standardIcon(QStyle::SP_FileIcon);

	const QPixmap iconPixmap = icon.pixmap(128, 128);
	if (iconPixmap.isNull())
		return;

	auto* dialog = new FileBreakDialog(iconPixmap, parent);
	dialog->show();
	dialog->startAnimation();
}