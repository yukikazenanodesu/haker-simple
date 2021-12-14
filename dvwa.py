# -*- coding: utf-8 -*-
from sys import exit
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from desters import *
import json

class windw(QMainWindow):

    core = None
    timer = None
    Monitor = None
    Forged = None

    def wdawdawdwasdw(self):
        selected_row = self.info_tree.currentItem().text(0)
        if selected_row and selected_row.isdigit():
            self.timer.stop()
            self.wdawdawdaw((int)(selected_row))
            if not self.core.pause_flag and not self.core.stop_flag:
                self.action_update.setDisabled(False)
    def wdawdawdaw(self, selected_row):
        self.treeWidget.clear()
        parentList, childList, hex_dump = self.core.wdadawdawdwa(selected_row)
        p_num = len(parentList)
        for i in range(p_num):
            item1 = QTreeWidgetItem(self.treeWidget)
            item1.setText(0, parentList[i])
            c_num = len(childList[i])
            for j in range(c_num):
                item1_1 = QTreeWidgetItem(item1)
                item1_1.setText(0, childList[i][j])
        self.set_hex_text(hex_dump)
    def dwadwadwawdaw(self):
        card = self.choose_nicbox.currentText()
        self.netNic.setText('here net card：' + card)
        if (card == 'All'):
            a = None
        elif waawdadw == 'Windows':
            a = wawdwaw[card]
        elif waawdadw == 'Linux':
            a = card
        else:
            a = None
        return a
    def set_hex_text(self, text):
        self.hexBrowser.setText(text)
    def one(self):
        if self.core.stop_flag:
            self.info_tree.clear()
            self.treeWidget.clear()
            self.set_hex_text("")
        self.core.mc5(self.dwadwadwawdaw(), self.Filter.text())
        self.start_action.setDisabled(True)
        self.Filter.setEnabled(False)
        self.FilterButton.setEnabled(False)
        self.choose_nicbox.setEnabled(False)
        self.actionRestart.setDisabled(False)
        self.pause_action.setEnabled(True)
        self.stop_action.setEnabled(True)
        self.timer.start(flush_time)
    def two(self):
        self.core.dosiuvs()
        self.start_action.setEnabled(True)
        self.stop_action.setDisabled(False)
        self.actionRestart.setDisabled(False)
        self.Filter.setDisabled(True)
        self.FilterButton.setDisabled(True)
        self.choose_nicbox.setDisabled(False)
        self.pause_action.setDisabled(True)
        self.action_update.setDisabled(True)
        self.timer.stop()
    def three(self):
        self.core.dscwas()
        self.stop_action.setDisabled(True)
        self.pause_action.setDisabled(True)
        self.start_action.setEnabled(True)
        self.Filter.setDisabled(False)
        self.FilterButton.setDisabled(False)
        self.choose_nicbox.setDisabled(False)
        self.action_update.setDisabled(True)
        self.timer.stop()
    def forew(self):
        self.timer.stop()
        self.core.mcw2(self.dwadwadwawdaw(), self.Filter.text())
        self.info_tree.clear()
        self.treeWidget.clear()
        self.set_hex_text("")
        self.actionRestart.setDisabled(False)
        self.start_action.setDisabled(True)
        self.Filter.setEnabled(False)
        self.FilterButton.setEnabled(False)
        self.choose_nicbox.setEnabled(False)
        self.pause_action.setEnabled(True)
        self.stop_action.setEnabled(True)
        self.timer.start(flush_time)
    def dadwwa(self, event):
        self.closeEvent(event)
    def closeEvent(self, QCloseEvent):
        def close_to_do():
            self.core.wdsxv()
            if self.Monitor and self.Monitor.is_alive():
                self.Monitor.terminate()
            if self.Forged and self.Forged.is_alive():
                self.Forged.terminate()
            exit()

        if self.core.start_flag or self.core.pause_flag:
            reply = QMessageBox.question(
                self, 'Message', "save or not save",
                QMessageBox.Save | QMessageBox.Close | QMessageBox.Cancel,
                QMessageBox.Cancel)
            if reply == QMessageBox.Cancel:
                QCloseEvent.ignore()
            if reply == QMessageBox.Close:
                self.core.dscwas()
                close_to_do()
            elif reply == QMessageBox.Save:
                self.core.dscwas()
                self.on_action_savefile_clicked()
                close_to_do()
        elif self.core.stop_flag and not self.core.save_flag:
            reply = QMessageBox.question(
                self, 'Message', "save or not save",
                QMessageBox.Save | QMessageBox.Close | QMessageBox.Cancel,
                QMessageBox.Cancel)
            if reply == QMessageBox.Cancel:
                QCloseEvent.ignore()
            elif reply == QMessageBox.Save:
                self.on_action_savefile_clicked()
                close_to_do()
            else:
                close_to_do()
        elif self.core.save_flag or not self.core.start_flag:
            reply = QMessageBox.question(self, 'Message', "queite?",
                                         QMessageBox.Yes | QMessageBox.No,
                                         QMessageBox.No)
            if reply == QMessageBox.Yes:
                close_to_do()
            else:
                QCloseEvent.ignore()
    def paintEvent(self, a0: QPaintEvent):
        painter = QPainter(self)
        pixmap = QPixmap("img/background.jpg")
        painter.drawPixmap(self.rect(), pixmap)
    def wdid(self):
        self.setWindowTitle("hacker")
        self.resize(950, 580)
        icon = QIcon()
        icon.addPixmap(QPixmap("img/1605833136708.jpeg"), QIcon.Normal, QIcon.Off)
        self.setWindowIcon(icon)
        self.setIconSize(QSize(20, 20))
        self.centralWidget = QWidget(self)
        self.centralWidget.setStyleSheet("background:transparent;")
        self.gridLayout = QGridLayout(self.centralWidget)
        self.gridLayout.setContentsMargins(0, 0, 0, 0)
        self.gridLayout.setSpacing(7)
        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setContentsMargins(11, 2, 11, 1)
        self.horizontalLayout.setSpacing(20)
        self.verticalLayout = QVBoxLayout()
        self.verticalLayout.setContentsMargins(11, 0, 3, 11)
        self.verticalLayout.setSpacing(7)
        font = QFont()
        with open('data.json', 'r') as file_obj:
            old_font = json.load(file_obj)
        if old_font["font"]:
            font.setFamily(old_font["font"])
            font.setPointSize(int(old_font["size"]))
        else:
            if waawdadw == 'Windows':
                font.setFamily("Lucida Sans Typewriter")
                old_font["font"] = "Lucida Sans Typewriter"
            if waawdadw == "Linux":
                font.setFamily("Noto Mono")
                old_font["font"] = "Noto Mono"
            font.setPointSize(11)
            with open('data.json', 'w') as file_obj:
                '''写入json文件'''
                json.dump(old_font, file_obj)
        self.info_tree = QTreeWidget(self.centralWidget)
        self.info_tree.setFrameStyle(QFrame.Box | QFrame.Plain)
        self.info_tree.setAutoScroll(True)
        self.info_tree.setRootIsDecorated(False)
        self.info_tree.setFont(font)
        self.info_tree.setColumnCount(7)
        self.info_tree.setUniformRowHeights(True)
        self.info_tree.headerItem().setText(0, "No.")
        self.info_tree.headerItem().setText(1, "Time")
        self.info_tree.headerItem().setText(2, "Source")
        self.info_tree.headerItem().setText(3, "Destination")
        self.info_tree.headerItem().setText(4, "Protocol")
        self.info_tree.headerItem().setText(5, "Length")
        self.info_tree.headerItem().setText(6, "Info")
        self.info_tree.setStyleSheet("background:transparent;")
        self.info_tree.setSortingEnabled(True)
        self.info_tree.sortItems(0, Qt.AscendingOrder)
        self.info_tree.setColumnWidth(0, 75)
        self.info_tree.setColumnWidth(1, 130)
        self.info_tree.setColumnWidth(2, 150)
        self.info_tree.setColumnWidth(3, 150)
        self.info_tree.setColumnWidth(4, 85)
        self.info_tree.setColumnWidth(5, 60)
        for i in range(7):
            self.info_tree.headerItem().setBackground(i,
                                                      QBrush(QColor(Qt.white)))
        self.info_tree.setSelectionBehavior(
            QTreeWidget.SelectRows)
        self.info_tree.setSelectionMode(QTreeWidget.SingleSelection)
        self.info_tree.header().setSortIndicatorShown(True)
        self.info_tree.clicked.connect(self.wdawdawdwasdw)
        self.treeWidget = QTreeWidget(self.centralWidget)
        self.treeWidget.setAutoScroll(True)
        self.treeWidget.setTextElideMode(Qt.ElideMiddle)
        self.treeWidget.header().setStretchLastSection(True)
        self.treeWidget.setStyleSheet("background:transparent; color:white;")
        self.treeWidget.header().hide()
        self.treeWidget.setFont(font)
        self.treeWidget.setColumnCount(1)
        self.treeWidget.setFrameStyle(QFrame.Box | QFrame.Plain)
        self.hexBrowser = QTextBrowser(self.centralWidget)
        self.hexBrowser.setText("")
        self.hexBrowser.setFont(font)
        self.hexBrowser.setStyleSheet("background:transparent;  color:white;")
        self.hexBrowser.setFrameStyle(QFrame.Box | QFrame.Plain)
        self.splitter = QSplitter(Qt.Vertical)
        self.splitter.addWidget(self.info_tree)
        self.splitter.addWidget(self.treeWidget)
        self.splitter.addWidget(self.hexBrowser)
        self.verticalLayout.addWidget(self.splitter)
        self.gridLayout.addLayout(self.verticalLayout, 1, 0, 1, 1)
        self.Filter = QLineEdit(self.centralWidget)
        self.Filter.setPlaceholderText("net work???? … ")
        self.Filter.setStyleSheet("background:white")
        self.Filter.setFont(font)
        self.horizontalLayout.addWidget(self.Filter)
        self.FilterButton = QPushButton(self.centralWidget)
        self.FilterButton.setText("start")
        icon1 = QIcon()
        icon1.addPixmap(QPixmap("img/redygo.jpg"), QIcon.Normal, QIcon.Off)
        self.FilterButton.setIcon(icon1)
        self.FilterButton.setIconSize(QSize(20, 20))
        self.FilterButton.setStyleSheet("background:white")
        self.FilterButton.clicked.connect(self.one)
        self.horizontalLayout.addWidget(self.FilterButton)
        self.choose_nicbox = QComboBox(self.centralWidget)
        self.choose_nicbox.setFont(font)
        self.choose_nicbox.setStyleSheet("background:white; color:black;")
        self.horizontalLayout.addWidget(self.choose_nicbox)
        self.horizontalLayout.setStretch(0, 8)
        self.horizontalLayout.setStretch(1, 1)
        self.horizontalLayout.setStretch(2, 4)
        self.gridLayout.addLayout(self.horizontalLayout, 0, 0, 1, 1)
        row_num = len(keys)
        self.choose_nicbox.addItem("All")
        for i in range(row_num):
            self.choose_nicbox.addItem(keys[i])

        self.setCentralWidget(self.centralWidget)
        self.menuBar = QMenuBar(self)
        self.menuBar.setGeometry(QRect(0, 0, 0,0))
        self.menuBar.setAccessibleName("")
        self.menuBar.setDefaultUp(True)
        self.mainToolBar = QToolBar(self)
        self.addToolBar(Qt.TopToolBarArea, self.mainToolBar)
        self.statusBar = QStatusBar(self)
        self.mainToolBar.setStyleSheet("background: #EDEDED;")
        self.mainToolBar.setMaximumHeight(25)
        self.setStatusBar(self.statusBar)
        self.start_action = QAction(self)
        icon2 = QIcon()
        icon2.addPixmap(QPixmap("img/start.png"), QIcon.Normal, QIcon.Off)
        self.start_action.setIcon(icon2)
        self.start_action.setText("start")
        self.start_action.setShortcut('F1')
        self.start_action.triggered.connect(self.one)
        self.stop_action = QAction(self)
        icon3 = QIcon()
        icon3.addPixmap(QPixmap("img/stop.png"), QIcon.Normal, QIcon.Off)
        self.stop_action.setIcon(icon3)
        self.stop_action.setText("sotp")
        self.stop_action.setShortcut('F3')
        self.stop_action.setDisabled(True)
        self.stop_action.triggered.connect(self.three)
        self.pause_action = QAction(self)
        p_icon = QIcon()
        p_icon.addPixmap(QPixmap("img/pause.png"), QIcon.Normal, QIcon.Off)
        self.pause_action.setIcon(p_icon)
        self.pause_action.setText("stop")
        self.pause_action.setShortcut('F2')
        self.pause_action.setDisabled(True)
        self.pause_action.triggered.connect(self.two)
        self.actionRestart = QAction(self)
        icon4 = QIcon()
        icon4.addPixmap(QPixmap("img/restart.png"), QIcon.Normal, QIcon.Off)
        self.actionRestart.setIcon(icon4)
        self.actionRestart.setText("restart")
        self.actionRestart.setShortcut('F4')
        self.actionRestart.setDisabled(True)
        self.actionRestart.triggered.connect(self.forew)
        self.action_update = QAction(self)
        icon5 = QIcon()
        icon5.addPixmap(QPixmap("img/update.png"), QIcon.Normal, QIcon.Off)
        self.action_update.setIcon(icon5)
        self.action_update.setText("continue")
        self.action_update.setShortcut('F5')
        self.action_update.setDisabled(True)
        self.action_update.triggered.connect(
            lambda: self.timer.start(flush_time) and self.action_update.setDisabled(True)
        )
        self.action_exit = QAction(self)
        self.action_exit.setCheckable(False)
        self.action_exit.setText("quite")
        self.action_exit.triggered.connect(self.dadwwa)
        self.action_exit.setShortcut('ctrl+Q')
        self.action_exit.setStatusTip('exit')
        self.mainToolBar.addAction(self.start_action)
        self.mainToolBar.addAction(self.pause_action)
        self.mainToolBar.addAction(self.stop_action)
        self.mainToolBar.addAction(self.actionRestart)
        self.mainToolBar.addAction(self.action_update)
        self.comNum = QLabel('downpackge')
        self.baudNum = QLabel('uploadpackge')
        self.getSpeed = QLabel('recive')
        self.sendSpeed = QLabel('sent')
        self.netNic = QLabel('Welcome to yukikaze!)
        self.statusBar.setStyleSheet("background: #EDEDED;")
        self.statusBar.addPermanentWidget(self.netNic, stretch=2)
        self.statusBar.addPermanentWidget(self.getSpeed, stretch=1)
        self.statusBar.addPermanentWidget(self.sendSpeed, stretch=1)
        self.statusBar.addPermanentWidget(self.comNum, stretch=1)
        self.statusBar.addPermanentWidget(self.baudNum, stretch=1)
        QMetaObject.connectSlotsByName(self)
        self.core = Core(self)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.info_tree.scrollToBottom)
        self.show()
def start():
    app = QApplication([])
    ui = windw()
    ui.wdid()
    app.exec()
