# -*- coding: utf-8 -*-
import json
from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from burp import IMessageEditorController

# Java UI Imports
from java.awt import BorderLayout, FlowLayout, GridBagLayout, GridBagConstraints, Insets, Color, Dimension
from java.io import PrintWriter
from java.util import ArrayList
from javax.swing import JScrollPane, JSplitPane, JTable, JPanel, JLabel, JTextField, JButton, JCheckBox, BorderFactory, SwingConstants
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer
from java.lang import Object, Integer
from threading import Lock

class BurpExtender(IBurpExtender, IHttpListener, ITab, IMessageEditorController):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Auto PoC (V17 Optimized UI)")
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._log = ArrayList()
        self._lock = Lock()
        self._id_counter = 0 
        
        self._init_ui()
        
        callbacks.customizeUiComponent(self._main_split_pane)
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        self._stdout.println("Plugin Loaded. UI Optimized: Split View & Method Column.")
        
    def _init_ui(self):
        # --- 配置面板 (右侧) ---
        config_panel = JPanel(GridBagLayout())
        config_panel.setBorder(BorderFactory.createTitledBorder("Configuration"))
        config_panel.setMinimumSize(Dimension(250, 0))
        
        c = GridBagConstraints()
        c.fill = GridBagConstraints.HORIZONTAL
        c.insets = Insets(5, 5, 5, 5) 
        c.anchor = GridBagConstraints.NORTHWEST
        
        def add_config_item(row, label_text, default_value):
            c.gridx = 0; c.gridy = row; c.weightx = 1.0
            config_panel.add(JLabel(label_text), c)
            c.gridy = row + 1
            tf = JTextField(default_value, 20)
            config_panel.add(tf, c)
            return tf, row + 2

        current_row = 0
        self.tf_domain, current_row = add_config_item(current_row, "Target Domain (Empty=ALL):", "")
        self.tf_param, current_row  = add_config_item(current_row, "Target Params (split by |):", "name|user|account")
        
        # 模糊匹配开关
        c.gridy = current_row
        c.gridx = 0
        self.chk_fuzzy = JCheckBox("Fuzzy Match (e.g. 'name' matches 'test_name')", False)
        config_panel.add(self.chk_fuzzy, c)
        current_row += 1
        
        self.tf_poc, current_row = add_config_item(current_row, "PoC Payload:", "<img src=x onerror=alert(1)>")
        
        # 底部开关和按钮
        c.gridy = current_row
        c.gridx = 0
        # 【修改点1】默认设为 False (关闭)
        self.chk_enable = JCheckBox("Enable Plugin", False) 
        config_panel.add(self.chk_enable, c)
        
        c.gridy = current_row + 1
        self.btn_clear = JButton("Clear Logs", actionPerformed=self.clear_logs)
        config_panel.add(self.btn_clear, c)
        
        c.gridy = current_row + 2
        c.weighty = 1.0 
        config_panel.add(JLabel(""), c)

        # --- 表格 (左侧) ---
        self.logTable = Table(self)
        scrollPane = JScrollPane(self.logTable)
        
        # --- 顶部布局组合 (左:表格, 右:配置) ---
        top_split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        top_split_pane.setLeftComponent(scrollPane)
        top_split_pane.setRightComponent(config_panel)
        top_split_pane.setResizeWeight(0.85)
        
        # --- 底部布局 (Request / Response) ---
        self._requestViewer = self._callbacks.createMessageEditor(self, False)
        self._responseViewer = self._callbacks.createMessageEditor(self, False)
        
        # 【修改点2】移除 Tab，改为左右 SplitPane
        bottom_split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        
        # 左下：Request
        request_panel = JPanel(BorderLayout())
        request_panel.add(JLabel("Request"), BorderLayout.NORTH)
        request_panel.add(self._requestViewer.getComponent(), BorderLayout.CENTER)
        
        # 右下：Response
        response_panel = JPanel(BorderLayout())
        response_panel.add(JLabel("Response"), BorderLayout.NORTH)
        response_panel.add(self._responseViewer.getComponent(), BorderLayout.CENTER)

        bottom_split_pane.setLeftComponent(request_panel)
        bottom_split_pane.setRightComponent(response_panel)
        bottom_split_pane.setResizeWeight(0.5) # 左右各占 50%
        
        # --- 主布局 (上:列表+配置, 下:详情) ---
        self._main_split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._main_split_pane.setTopComponent(top_split_pane)
        self._main_split_pane.setBottomComponent(bottom_split_pane)
        self._main_split_pane.setResizeWeight(0.5)

    def getTabCaption(self): return "Poc Logger"
    def getUiComponent(self): return self._main_split_pane

    def clear_logs(self, event):
        self._lock.acquire()
        self._log.clear()
        self._id_counter = 0
        self.logTable.getModel().fireTableDataChanged()
        self._lock.release()

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # 必须勾选开启且必须是 Request
        if not self.chk_enable.isSelected(): return
        if not messageIsRequest: return
        
        try:
            target_domain = self.tf_domain.getText().strip()
            raw_param_text = self.tf_param.getText().strip()
            if not raw_param_text: return
            
            target_params = set([x.strip() for x in raw_param_text.split('|') if x.strip()])
            is_fuzzy_mode = self.chk_fuzzy.isSelected()
            poc_payload = self.tf_poc.getText()
            
            httpService = messageInfo.getHttpService()
            request_info = self._helpers.analyzeRequest(messageInfo)
            
            if target_domain and (target_domain not in httpService.getHost()): return
            
            # 获取 Method 用于后续显示和过滤
            method = request_info.getMethod().upper()
            if method not in ["POST", "PUT"]: return

            request_bytes = messageInfo.getRequest()
            body_offset = request_info.getBodyOffset()
            body_bytes = request_bytes[body_offset:]
            body_str = self._helpers.bytesToString(body_bytes)
            
            try:
                json_data = json.loads(body_str)
            except ValueError:
                return

            is_modified = [False]
            
            def recursive_update(data):
                if isinstance(data, dict):
                    for k, v in data.items():
                        should_inject = False
                        if is_fuzzy_mode:
                            for target in target_params:
                                if target in k:
                                    should_inject = True
                                    break
                        else:
                            if k in target_params:
                                should_inject = True

                        if should_inject:
                            original_val = unicode(v) if isinstance(v, str) else str(v)
                            if poc_payload not in original_val:
                                data[k] = original_val + poc_payload
                                is_modified[0] = True
                        
                        if isinstance(v, (dict, list)):
                            recursive_update(v)
                elif isinstance(data, list):
                    for item in data:
                        recursive_update(item)

            recursive_update(json_data)
            
            if is_modified[0]:
                new_body_str = json.dumps(json_data)
                new_body_bytes = self._helpers.stringToBytes(new_body_str)
                headers = request_info.getHeaders()
                new_request_bytes = self._helpers.buildHttpMessage(headers, new_body_bytes)
                
                checkRequestResponse = self._callbacks.makeHttpRequest(httpService, new_request_bytes)
                
                response_bytes = checkRequestResponse.getResponse()
                if response_bytes:
                    status_code = self._helpers.analyzeResponse(response_bytes).getStatusCode()
                    is_success = (status_code == 200)
                    
                    self._lock.acquire()
                    self._id_counter += 1
                    current_id = self._id_counter
                    row = self._log.size()
                    # 【修改点3】存入 method
                    self._log.add(LogEntry(current_id, toolFlag, checkRequestResponse, method, request_info.getUrl(), status_code, is_success))
                    self.fireTableRowsInserted(row, row)
                    self._lock.release()

        except Exception as e:
            self._stdout.println("  [!] Error: " + str(e))

    # --- UI 辅助方法 ---
    def fireTableRowsInserted(self, firstRow, lastRow):
        self.logTable.getModel().fireTableRowsInserted(firstRow, lastRow)
    def getHttpService(self): return self._currentlySelectedLogEntry.requestResponse.getHttpService()
    def getRequest(self): return self._currentlySelectedLogEntry.requestResponse.getRequest()
    def getResponse(self): return self._currentlySelectedLogEntry.requestResponse.getResponse()

# 【修改点3】LogEntry 增加 method 字段
class LogEntry:
    def __init__(self, id, tool, requestResponse, method, url, status, is_success):
        self.id = id
        self.tool = tool
        self.requestResponse = requestResponse
        self.method = method # 新增
        self.url = url
        self.status = status 
        self.is_success = is_success

class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(LogTableModel(extender))
        self.setDefaultRenderer(Object, GreenColorRenderer())
        self.setAutoCreateRowSorter(True)
        
        # 设置列宽
        self.getColumnModel().getColumn(0).setPreferredWidth(40)  # ID
        self.getColumnModel().getColumn(0).setMaxWidth(60)
        self.getColumnModel().getColumn(1).setPreferredWidth(60)  # Method (新增)
        self.getColumnModel().getColumn(1).setMaxWidth(80)
        self.getColumnModel().getColumn(3).setPreferredWidth(60)  # Status
        self.getColumnModel().getColumn(3).setMaxWidth(80)
        # URL 自动填充剩余空间
    
    def changeSelection(self, row, col, toggle, extend):
        modelRow = self.convertRowIndexToModel(row)
        LogEntry = self._extender._log.get(modelRow)
        # 点击行时，同时更新左右两侧
        self._extender._requestViewer.setMessage(LogEntry.requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(LogEntry.requestResponse.getResponse(), False)
        self._extender._currentlySelectedLogEntry = LogEntry
        JTable.changeSelection(self, row, col, toggle, extend)

class LogTableModel(AbstractTableModel):
    def __init__(self, extender): self._extender = extender
    def getRowCount(self): return self._extender._log.size()
    
    # 【修改点3】列数变为 4
    def getColumnCount(self): return 4 
    
    # 【修改点3】增加 Method 列名
    def getColumnName(self, c): 
        return ["ID", "Method", "URL", "Status"][c]
    
    def getColumnClass(self, columnIndex):
        if columnIndex == 0 or columnIndex == 3: return Integer 
        return Object
        
    def getValueAt(self, r, c):
        entry = self._extender._log.get(r)
        if c==0: return entry.id
        if c==1: return entry.method # 返回 Method
        if c==2: return entry.url.toString()
        if c==3: return entry.status
        return ""

class GreenColorRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = super(GreenColorRenderer, self).getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
        
        # ID(0), Method(1), Status(3) 居中显示
        if column in [0, 1, 3]:
            self.setHorizontalAlignment(SwingConstants.CENTER)
        else:
            self.setHorizontalAlignment(SwingConstants.LEFT)
            
        modelRow = table.convertRowIndexToModel(row)
        entry = table.getModel()._extender._log.get(modelRow)
        if not isSelected:
            c.setBackground(Color.GREEN if entry.is_success else Color.WHITE)
            c.setForeground(Color.BLACK)
        return c