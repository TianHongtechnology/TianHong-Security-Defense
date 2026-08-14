/****************************************************************************
** Meta object code from reading C++ file 'ActiveIcon.h'
**
** Created by: The Qt Meta Object Compiler version 69 (Qt 6.9.2)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../ActiveIcon.h"
#include <QtCore/qmetatype.h>

#include <QtCore/qtmochelpers.h>

#include <memory>


#include <QtCore/qxptype_traits.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'ActiveIcon.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 69
#error "This file was generated using the moc from 6.9.2. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

#ifndef Q_CONSTINIT
#define Q_CONSTINIT
#endif

QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
QT_WARNING_DISABLE_GCC("-Wuseless-cast")
namespace {
struct qt_meta_tag_ZN10ActiveIcon20StateIndicatorWidgetE_t {};
} // unnamed namespace

template <> constexpr inline auto ActiveIcon::StateIndicatorWidget::qt_create_metaobjectdata<qt_meta_tag_ZN10ActiveIcon20StateIndicatorWidgetE_t>()
{
    namespace QMC = QtMocConstants;
    QtMocHelpers::StringRefStorage qt_stringData {
        "ActiveIcon::StateIndicatorWidget",
        "pulseFactor",
        "breathIntensity",
        "morphProgress",
        "currentColor",
        "borderGlow"
    };

    QtMocHelpers::UintData qt_methods {
    };
    QtMocHelpers::UintData qt_properties {
        // property 'pulseFactor'
        QtMocHelpers::PropertyData<qreal>(1, QMetaType::QReal, QMC::DefaultPropertyFlags | QMC::Writable | QMC::StdCppSet),
        // property 'breathIntensity'
        QtMocHelpers::PropertyData<qreal>(2, QMetaType::QReal, QMC::DefaultPropertyFlags | QMC::Writable | QMC::StdCppSet),
        // property 'morphProgress'
        QtMocHelpers::PropertyData<qreal>(3, QMetaType::QReal, QMC::DefaultPropertyFlags | QMC::Writable | QMC::StdCppSet),
        // property 'currentColor'
        QtMocHelpers::PropertyData<QColor>(4, QMetaType::QColor, QMC::DefaultPropertyFlags | QMC::Writable | QMC::StdCppSet),
        // property 'borderGlow'
        QtMocHelpers::PropertyData<qreal>(5, QMetaType::QReal, QMC::DefaultPropertyFlags | QMC::Writable | QMC::StdCppSet),
    };
    QtMocHelpers::UintData qt_enums {
    };
    return QtMocHelpers::metaObjectData<StateIndicatorWidget, qt_meta_tag_ZN10ActiveIcon20StateIndicatorWidgetE_t>(QMC::MetaObjectFlag{}, qt_stringData,
            qt_methods, qt_properties, qt_enums);
}
Q_CONSTINIT const QMetaObject ActiveIcon::StateIndicatorWidget::staticMetaObject = { {
    QMetaObject::SuperData::link<QWidget::staticMetaObject>(),
    qt_staticMetaObjectStaticContent<qt_meta_tag_ZN10ActiveIcon20StateIndicatorWidgetE_t>.stringdata,
    qt_staticMetaObjectStaticContent<qt_meta_tag_ZN10ActiveIcon20StateIndicatorWidgetE_t>.data,
    qt_static_metacall,
    nullptr,
    qt_staticMetaObjectRelocatingContent<qt_meta_tag_ZN10ActiveIcon20StateIndicatorWidgetE_t>.metaTypes,
    nullptr
} };

void ActiveIcon::StateIndicatorWidget::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    auto *_t = static_cast<StateIndicatorWidget *>(_o);
    if (_c == QMetaObject::ReadProperty) {
        void *_v = _a[0];
        switch (_id) {
        case 0: *reinterpret_cast<qreal*>(_v) = _t->pulseFactor(); break;
        case 1: *reinterpret_cast<qreal*>(_v) = _t->breathIntensity(); break;
        case 2: *reinterpret_cast<qreal*>(_v) = _t->morphProgress(); break;
        case 3: *reinterpret_cast<QColor*>(_v) = _t->currentColor(); break;
        case 4: *reinterpret_cast<qreal*>(_v) = _t->borderGlow(); break;
        default: break;
        }
    }
    if (_c == QMetaObject::WriteProperty) {
        void *_v = _a[0];
        switch (_id) {
        case 0: _t->setPulseFactor(*reinterpret_cast<qreal*>(_v)); break;
        case 1: _t->setBreathIntensity(*reinterpret_cast<qreal*>(_v)); break;
        case 2: _t->setMorphProgress(*reinterpret_cast<qreal*>(_v)); break;
        case 3: _t->setCurrentColor(*reinterpret_cast<QColor*>(_v)); break;
        case 4: _t->setBorderGlow(*reinterpret_cast<qreal*>(_v)); break;
        default: break;
        }
    }
}

const QMetaObject *ActiveIcon::StateIndicatorWidget::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *ActiveIcon::StateIndicatorWidget::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_staticMetaObjectStaticContent<qt_meta_tag_ZN10ActiveIcon20StateIndicatorWidgetE_t>.strings))
        return static_cast<void*>(this);
    return QWidget::qt_metacast(_clname);
}

int ActiveIcon::StateIndicatorWidget::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QWidget::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::ReadProperty || _c == QMetaObject::WriteProperty
            || _c == QMetaObject::ResetProperty || _c == QMetaObject::BindableProperty
            || _c == QMetaObject::RegisterPropertyMetaType) {
        qt_static_metacall(this, _c, _id, _a);
        _id -= 5;
    }
    return _id;
}
QT_WARNING_POP
