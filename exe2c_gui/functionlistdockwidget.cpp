#include <QtCore>
#include "functionlistdockwidget.h"
#include "ui_functionlistdockwidget.h"
#include "exe2c.h"
extern I_EXE2C *g_EXE2C;
FunctionListDockWidget::FunctionListDockWidget(QWidget *parent) :
    QDockWidget(parent),
    ui(new Ui::FunctionListDockWidget)
{
    ui->setupUi(this);
    ui->m_func_list_view->setModel(&m_list_model);
}

FunctionListDockWidget::~FunctionListDockWidget()
{
    delete ui;
}
void FunctionListDockWidget::functionSelected(const QModelIndex &idx)
{
    QVariant v=m_list_model.data(idx,Qt::DisplayRole);
    qDebug()<<"neb changed function to "<<v;
    g_EXE2C->SetCurFunc_by_Name(v.toString().toStdString().c_str());
}
// signalled by m_func_list_view accepted signal
void FunctionListDockWidget::displayRequest(const QModelIndex &)
{
    // argument ignored since functionSelected must've been called before us
    emit displayRequested();
}
void FunctionListModel::updateFunctionList()
{
    rebuildFunctionList();
}
void FunctionListModel::rebuildFunctionList()
{
    FUNC_LIST::iterator iter = g_EXE2C->GetFirstFuncHandle();
    clear();
    beginInsertRows(QModelIndex(),0,g_EXE2C->GetFuncCount());

    while (g_EXE2C->is_valid_function_handle(iter))
    {
        st_FuncInfo info;
        memset(&info,0, sizeof(info));
        g_EXE2C->GetFuncInfo(iter, &info);
        iter = g_EXE2C->GetNextFuncHandle(iter);

        if (info.name[0] == 0)
            continue;
        add_function(info.name,info.nStep,info.headoff,info.endoff,info.stack_purge);
    }
    endInsertRows();
}
QVariant FunctionListModel::data(const QModelIndex &idx,int role) const
{
    int row=idx.row();
    int column=idx.column();
    const function_info &inf=m_list[row];
    if(Qt::DisplayRole==role)
    {
        switch(column)
        {
            case 0: // name
            {
                QString name(inf.m_name.c_str());
                return QVariant(name);
            }
            case 1: // step
                return QVariant(inf.m_decoding_step);
            case 2: // start offset
            {
                QString in_base_16=QString("%1").arg(inf.m_start_off,0,16);
                return QVariant(in_base_16);
            }
            default:
                return QVariant();

        }
    }
    return QVariant();
}
QVariant FunctionListModel::headerData(int section, Qt::Orientation orientation,int role) const
{
    if(Qt::DisplayRole==role && orientation==Qt::Horizontal)
    {
        switch(section)
        {
            case 0: // name
                return QObject::tr("Function name");
            case 1: // step
                return QObject::tr("Decoding step");
            case 2: // start offset
                return QObject::tr("Start offset");
            default:
                return QVariant();

        }
    }
    return QVariant();
}
