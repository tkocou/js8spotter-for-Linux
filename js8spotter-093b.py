# JS8Spotter v0.93a - 1/24/2021
#
# A small JS8Call API-based app to keep track of activity containing specific
# search terms, including callsigns or other activity. Matches on RX.ACTIVITY,
# RX.DIRECTED, and RX.SPOT only. Tested under Windows with JS8Call v2.2.0.
#
# Special thanks to KE0DHO, KF0HHR, and N0GES, for help in development
#
# Enable TCP API in JS8Call. File>Settings>Reporting, checkmark on Allow Setting
# Station Information, Enable TCP Server API, Accept TCP Requests.
#
# MIT License, Copyright 2022 Joseph D Lyman KF7MIX
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

import tkinter as tk
from tkinter import *
from tkinter import filedialog as fd
from tkinter import ttk, messagebox
from tkinter.ttk import Treeview, Style, Combobox
from tkinter.messagebox import askyesno
from threading import *
from threading import Thread
from io import StringIO
import time
import socket
import select
import json
import sqlite3
### Adding sys.exit() in main()
import sys
import os
### Added a check to js8spotter based on running OS - N4FWD
import platform
import js8spotter_initdb as init_DB
import linux_support as ls

### Globals
swname = "JS8Spotter for Linux"
fromtext = "de KF7MIX & N4FWD"
swversion = "0.93b.1"

base_dir = ""
tcp_conn = False

sysPlatform = platform.system()
if sysPlatform == "Linux":
    base_dir = init_DB.initialize_db()
    ls.make_support(base_dir)
    ls.create_launcher(base_dir)
###

dbfile = 'js8spotter.db'
conn = sqlite3.connect(dbfile)
c = conn.cursor()

current_profile_id = 0
search_strings = []
bgsearch_strings = {}

# Database settings table
c.execute("SELECT * FROM setting")
dbsettings = c.fetchall()

# Build any missing default settings
if len(dbsettings)<6:
    c.execute("INSERT INTO setting(name,value) VALUES ('udp_ip','127.0.0.1'),('udp_port','2242'),('tcp_ip','127.0.0.1'),('tcp_port','2442'),('hide_heartbeat','0'),('dark_theme','0')")
    conn.commit()
    # rebuild for the settings dictionary
    c.execute("SELECT * FROM setting")
    dbsettings.clear()
    dbsettings = c.fetchall()

# setup settings dictionary
settings = {}
for setting in dbsettings:
    settings[setting[1]]=setting[2]

# for inter-thread comms
event = Event()

### Thread for processing output of JS8Call over socket
class TCP_RX(Thread):
    def __init__(self, sock):
        super().__init__()
        self.sock = sock
        self.keep_running = True

    def stop(self):
        self.keep_running = False

    def run(self):
        conn1 = sqlite3.connect(dbfile)
        c1 = conn1.cursor()

        track_types = {"RX.ACTIVITY", "RX.DIRECTED", "RX.SPOT"}

        while self.keep_running:
            # check every 0.5sec
            rfds, _wfds, _xfds = select.select([self.sock], [], [], 0.5)
            if self.sock in rfds:
                try:
                    iodata = self.sock.recv(2048)
                    # tcp connection may return multiple json lines
                    json_lines = StringIO(str(iodata,'UTF-8'))
                    for data in json_lines:
                        try:
                            data_json = json.loads(data)
                        except ValueError as error:
                            data_json = {'type':'error'}

                        if data_json['type'] in track_types:
                            msg_call = ""
                            if "CALL" in data_json['params']:
                                msg_call = data_json['params']['CALL']
                            if "FROM" in data_json['params']:
                                msg_call = data_json['params']['FROM']

                            msg_dial = ""
                            if "DIAL" in data_json['params']:
                                msg_dial = data_json['params']['DIAL']

                            msg_snr = ""
                            if "SNR" in data_json['params']:
                                msg_snr = data_json['params']['SNR']

                            # if any search_string is in 'value' or 'call' then insert into db
                            # Check visible profile search terms
                            save_entry = False
                            # need to make a copy in case the other thread modifies the dict
                            searchcheck = search_strings.copy()
                            for term in searchcheck:
                                if term in msg_call:
                                    sql = "UPDATE search SET last_seen = CURRENT_TIMESTAMP WHERE profile_id = ? AND keyword = ?"
                                    c1.execute(sql, [current_profile_id,term])
                                    conn1.commit()
                                    save_entry = True

                                if term in data_json['value']:
                                    sql = "UPDATE search SET last_seen = CURRENT_TIMESTAMP WHERE profile_id = ? AND keyword = ?"
                                    c1.execute(sql, [current_profile_id,term])
                                    conn1.commit()
                                    save_entry = True

                            if save_entry == True:
                                sql = "INSERT INTO activity(profile_id,type,value,dial,snr,call,spotdate) VALUES (?,?,?,?,?,?, CURRENT_TIMESTAMP)"
                                c1.execute(sql, [current_profile_id,data_json['type'],data_json['value'],msg_dial,msg_snr,msg_call])
                                conn1.commit()
                                event.set()

                            # Check background scan profile terms
                            save_entry = False
                            # need to make a copy in case the other thread modifies the dict
                            bgcheck = bgsearch_strings.copy();
                            for term in bgcheck.keys():
                                term_profile = bgcheck.get(term)
                                if term in msg_call:
                                    sql = "UPDATE search SET last_seen = CURRENT_TIMESTAMP WHERE profile_id = ? AND keyword = ?"
                                    c1.execute(sql, [term_profile,term])
                                    conn1.commit()

                                    sql = "INSERT INTO activity(profile_id,type,value,dial,snr,call,spotdate) VALUES (?,?,?,?,?,?, CURRENT_TIMESTAMP)"
                                    c1.execute(sql, [term_profile,data_json['type'],data_json['value'],msg_dial,msg_snr,msg_call])
                                    conn1.commit()

                                    save_entry = True

                                if term in data_json['value']:
                                    sql = "UPDATE search SET last_seen = CURRENT_TIMESTAMP WHERE profile_id = ? AND keyword = ?"
                                    c1.execute(sql, [term_profile,term])
                                    conn1.commit()

                                    sql = "INSERT INTO activity(profile_id,type,value,dial,snr,call,spotdate) VALUES (?,?,?,?,?,?, CURRENT_TIMESTAMP)"
                                    c1.execute(sql, [term_profile,data_json['type'],data_json['value'],msg_dial,msg_snr,msg_call])
                                    conn1.commit()

                                    save_entry = True

                            if save_entry == True:
                                event.set()

                except socket.error as err:
                    print("Error at receiving socket {}".format(err))
                    break


### Main program thread
class App(tk.Tk):
    
    def __init__(self, sock):
        super().__init__()
        ### adding python check
        if sys.version_info < (3,8):
            messagebox.showwarning('Python version Error','Python version is not at the required 3.8 or higher')
            sys.exit()
        self.sock = sock
        self.sender = None
        self.receiver = None
        self.protocol("WM_DELETE_WINDOW", self.menu_bye)

        self.style = Style()
        self.call("source", "azure.tcl")

        self.create_gui()
        self.activate_theme()

        self.build_profilemenu()
        self.refresh_keyword_tree()
        self.refresh_activity_tree()

        ### we have a good tcp connection
        if tcp_conn:
            self.start_receiving()
            self.poll_activity()

        self.eval('tk::PlaceWindow . center')
        self.update()

    # Setup gui
    def create_gui(self):
        self.title(swname+" "+fromtext+" (v"+swversion+")")
        if sysPlatform == "Linux":
            ### adjustment necessary due to diff between
            ### Windows and Linux displays
            self.geometry('1000x400')
        else:
            self.geometry('900x400')
        self.resizable(width=False, height=False)

        self.columnconfigure(0, weight=12)
        self.columnconfigure(1, weight=1)
        self.columnconfigure(2, weight=12)
        self.columnconfigure(3, weight=1)

        self.rowconfigure(0,weight=1)
        self.rowconfigure(1,weight=1)
        self.rowconfigure(2,weight=24)
        self.rowconfigure(3,weight=6)

        # menus
        self.menubar = Menu(self)
        self.filemenu = Menu(self.menubar, tearoff = 0)
        self.profilemenu = Menu(self.menubar, tearoff = 0)

        self.filemenu.add_cascade(label = 'Switch Profile', menu = self.profilemenu)
        self.filemenu.add_separator()
        self.filemenu.add_command(label = 'New Profile', command = self.menu_new)
        self.filemenu.add_command(label = 'Edit Profile', command = self.menu_edit)
        self.filemenu.add_command(label = 'Remove Profile', command = self.menu_remove)
        ### Added ability to update the network settings
        self.filemenu.add_separator()
        self.filemenu.add_command(label = 'Network Settings', command = self.update_network)
        self.filemenu.add_separator()
        self.filemenu.add_command(label = 'Exit', command = self.menu_bye)

        self.viewmenu = Menu(self.menubar, tearoff = 0)
        self.viewmenu.add_command(label = "Hide Heartbeats", command = self.toggle_view_hb)
        self.viewmenu.add_command(label = "Dark Theme", command = self.toggle_theme)

        self.helpmenu = Menu(self.menubar, tearoff = 0)
        self.helpmenu.add_command(label = 'About', command = self.about)

        self.menubar.add_cascade(label = 'File', menu = self.filemenu)
        self.menubar.add_cascade(label = 'View', menu = self.viewmenu)
        self.menubar.add_cascade(label = 'Help', menu = self.helpmenu)
        self.config(menu = self.menubar)

        # Profile title and select
        self.prframe = ttk.Frame(self)
        self.prframe.grid(row=0, column=0, columnspan=2, sticky=NSEW, padx=10, pady=(0,5))

        self.profilemark = ttk.Label(self.prframe, text='Profile:', font=("Segoe Ui Bold", 14))
        self.profilemark.grid(row=0, column = 0, sticky='W', padx=0, pady=(8,0))
        self.profilecombo = ttk.Combobox(self.prframe, values="", state='readonly')
        self.profilecombo.grid(row=0, column =1 , sticky='E', padx=8, pady=(8,0))
        self.profilecombo.bind('<<ComboboxSelected>>', self.profile_sel_combo)

        # titles
        self.keywordmark = Label(self, text='Search Terms', fg='blue', font=("Segoe Ui", 12))
        self.keywordmark.grid(row=1, column = 0, sticky='W', padx=10)
        self.activitymark = Label(self, text="Matched Activity (last 100)", fg='purple', font=("Segoe Ui", 12))
        self.activitymark.grid(row=1, column = 2, sticky='W', padx=10)

        # background process checkbox
        self.current_profile_scan = IntVar()
        self.bgcheck = ttk.Checkbutton(self, text='Background Scan This Profile',variable=self.current_profile_scan, command=self.toggle_bg_scan)
        self.bgcheck.grid(row=0, column=2, sticky='E')

        # keyword treeview
        self.keywords = ttk.Treeview(self, show='headings', style='keywords.Treeview')
        self.keywords["columns"]=("search","last_seen")

        self.keywords.column("search")
        self.keywords.column("last_seen")

        self.keywords.heading("search", text="Search")
        self.keywords.heading("last_seen", text="Last Seen")

        self.keywords.bind('<Double-1>', self.view_keyword_activity)
        self.keywords.grid(row=2, column=0, sticky=NSEW, padx=(10,0), pady=(0,10))
        self.kwscrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.keywords.yview)
        self.keywords.configure(yscroll=self.kwscrollbar.set)
        self.kwscrollbar.grid(row=2, column=1, sticky=NS, padx=(0,0), pady=(0,10))

        # activity treeview
        self.activity = ttk.Treeview(self, show='headings', style='activity.Treeview', selectmode='browse')
        self.activity["columns"]=("type","value","stamp")

        self.activity.column('type', width=100, minwidth=100, stretch=0)
        self.activity.column('value', width=210, minwidth=210)
        self.activity.column('stamp', width=130, minwidth=130, stretch=0)

        self.activity.heading('type', text='Type')
        self.activity.heading('value', text='Activity')
        self.activity.heading('stamp', text='When')

        self.activity.bind('<Double-1>', self.view_activity)
        self.activity.grid(row=2, column=2, sticky=NSEW, padx=(10,0), pady=(0,10))
        self.acscrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.activity.yview)
        self.activity.configure(yscroll=self.acscrollbar.set)
        self.acscrollbar.grid(row=2, column=3, sticky=NS, padx=(0,10), pady=(0,10))

        # add inputs and buttons below treeviews
        self.kwframe = Frame(self)
        self.kwframe.grid(row=3, column=0, columnspan=2, sticky=NSEW, padx=10, pady=(0,10))
        self.new_keyword = ttk.Entry(self.kwframe, width = '14')
        self.new_keyword.grid(row = 0, column = 0)
        self.new_keyword.bind('<Return>', lambda x: self.proc_addkw())

        self.addkw_button = ttk.Button(self.kwframe, text = 'Add', command = self.proc_addkw, width='6')
        self.addkw_button.grid(row=0, column = 1, padx=(8,8))
        self.removekw_button = ttk.Button(self.kwframe, text = 'Remove', command = self.proc_remkw, width='8')
        self.removekw_button.grid(row=0, column = 2)


        self.addbat_button = ttk.Button(self.kwframe, text = 'Import', command = self.add_batch, width='6')
        self.addbat_button.grid(row=0, column = 3, padx=(28,0))
        self.expbat_button = ttk.Button(self.kwframe, text = 'Export', command = self.proc_exportsearch, width='6')
        self.expbat_button.grid(row=0, column = 4, padx=8)

        self.acframe = ttk.Frame(self)
        self.acframe.grid(row=3, column=2, sticky=NE)
        self.expact_button = ttk.Button(self.acframe, text = 'Export Log', command = self.proc_exportlog)
        self.expact_button.grid(row=0, column=0, sticky='NE', padx=(0,8), pady=0)
        self.clearact_button = ttk.Button(self.acframe, text = 'Clear Log', command = self.proc_dellog)
        self.clearact_button.grid(row=0, column=1, sticky='NE', padx=0, pady=0)


    # select light/dark theme
    def toggle_theme(self):
        global settings
        if settings['dark_theme'] == "1":
            c.execute("UPDATE setting SET value = '0' WHERE name = 'dark_theme'")
            conn.commit()
            settings['dark_theme'] = "0"
        else:
            c.execute("UPDATE setting SET value = '1' WHERE name = 'dark_theme'")
            conn.commit()
            settings['dark_theme'] = "1"
        self.activate_theme()


    # activate the current theme
    def activate_theme(self):
        if settings['dark_theme'] == "1":
            self.viewmenu.entryconfigure(1, label="\u2713 Dark Theme")
            self.call("set_theme", "dark")
            self.keywordmark.configure(fg='#6699FF')
            self.activitymark.configure(fg='#CC66FF')
            self.style.map('keywords.Treeview', background=[('selected', '#4477FF')])
            self.style.map('activity.Treeview', background=[('selected', '#AA44FF')])
            self.activity.tag_configure('oddrow', background='#777')
            self.activity.tag_configure('evenrow', background='#555')
            self.keywords.tag_configure('oddrow', background='#777')
            self.keywords.tag_configure('evenrow', background='#555')
        else:
            self.viewmenu.entryconfigure(1, label="Dark Theme")
            self.call("set_theme", "light")
            self.keywordmark.configure(fg='#4477FF')
            self.activitymark.configure(fg='#AA44FF')
            self.style.map('keywords.Treeview', background=[('selected', '#6699FF')])
            self.style.map('activity.Treeview', background=[('selected', '#CC66FF')])
            self.activity.tag_configure('oddrow', background='#FFF')
            self.activity.tag_configure('evenrow', background='#EEE')
            self.keywords.tag_configure('oddrow', background='#FFF')
            self.keywords.tag_configure('evenrow', background='#EEE')
        self.update()


    # Add keyword to database/tree
    def proc_addkw(self):
        new_kw = self.new_keyword.get().upper()
        if new_kw == "":
            return
        c.execute("SELECT * FROM search WHERE profile_id = ? AND keyword = ?", [current_profile_id,new_kw])
        kw_exists = c.fetchone()
        if not kw_exists:
            c.execute("INSERT INTO search(profile_id,keyword) VALUES (?,?)", [current_profile_id,new_kw])
            conn.commit()
            self.refresh_keyword_tree()
        self.new_keyword.delete(0,END)


    # Add a batch of keywords
    def add_batch(self):
        self.top = Toplevel(self)
        self.top.title("Add Batch of Search Terms")
        self.top.geometry('400x500')

        self.addbatmark = ttk.Label(self.top, text="Type or paste search terms, one per line", font=('10'))
        self.addbatmark.pack(side=TOP, anchor=NW, padx=10, pady=10)

        # save button
        tlframe = ttk.Frame(self.top)
        tlframe.pack(side=BOTTOM, anchor=SW, padx=10, pady=(0,10))
        self.save_button = ttk.Button(tlframe, text = 'Add Batch', command = self.proc_addbatch)
        self.save_button.pack(side=LEFT, padx=(0,10))

        # Text window
        self.batch = Text(self.top, wrap=NONE)
        batch_scrollbar = ttk.Scrollbar(self.top)
        batch_scrollbar.pack(side=RIGHT, fill='y', padx=(0,10), pady=(0,10))
        batch_scrollbar.config(command=self.batch.yview)
        self.batch.pack(side=LEFT, expand=True, fill='both', padx=(10,0), pady=(0,10))

        self.top.focus()
        self.top.grab_set()
        self.top.bind('<Escape>', lambda x: self.top.destroy())


    # add multiple search terms at once
    def proc_addbatch(self):
        batch_values = StringIO(self.batch.get('1.0','end'))
        for line in batch_values:
            new_kw = line.rstrip().upper()
            if new_kw == "":
                continue
            c.execute("SELECT * FROM search WHERE profile_id = ? AND keyword = ?", [current_profile_id,new_kw])
            kw_exists = c.fetchone()
            if not kw_exists:
                c.execute("INSERT INTO search(profile_id,keyword) VALUES (?,?)", [current_profile_id,new_kw])
                conn.commit()
        self.top.destroy()
        self.refresh_keyword_tree()


    # export search terms
    def proc_exportsearch(self):
        self.top = Toplevel(self)
        self.top.title("Export Search Terms")
        self.top.geometry('400x500')

        self.exportmark = ttk.Label(self.top, text="Copy/Export Search Terms", font=('10'))
        self.exportmark.pack(side=TOP, anchor=NW, padx=10, pady=10)

        # save and copy buttons
        tlframe = ttk.Frame(self.top)
        tlframe.pack(side=BOTTOM, anchor=SW, padx=10, pady=(0,10))
        self.copy_button = ttk.Button(tlframe, text = 'Copy All', command = self.export_copy_all)
        self.copy_button.pack(side=LEFT, padx=(0,10))
        self.saveas_button = ttk.Button(tlframe, text = 'Save As', command = self.export_saveas_popup)
        self.saveas_button.pack(side=RIGHT)

        # Text window
        self.export_text = Text(self.top, wrap=NONE)
        export_scrollbar = ttk.Scrollbar(self.top)
        export_scrollbar.pack(side=RIGHT, fill='y', padx=(0,10), pady=(0,10))
        export_scrollbar.config(command=self.export_text.yview)
        self.export_text.pack(side=LEFT, expand=True, fill='both', padx=(10,0), pady=(0,10))

        # right-click action
        self.rcmenu = Menu(self.top, tearoff = 0)
        self.rcmenu.add_command(label = 'Copy')
        self.export_text.bind('<Button-3>', lambda ev: self.export_copy_popup(ev))

        c.execute("SELECT * FROM search WHERE profile_id = ? ORDER BY last_seen DESC",[current_profile_id])
        export_kw_records = c.fetchall()

        for record in export_kw_records:
            insert_rec = record[2]+"\n"
            self.export_text.insert(tk.END, insert_rec)

        self.top.focus()
        self.top.grab_set()
        self.top.bind('<Escape>', lambda x: self.top.destroy())


    # Remove keyword from database/tree
    def proc_remkw(self):
        kwlist = ""
        for kwiid in self.keywords.selection():
            kwlist += self.keywords.item(kwiid)['values'][0]+"\n"

        if kwlist == "":
            return

        msgtxt = "Remove the following search term(s)?\n"+kwlist
        answer = askyesno(title='Remove Search Term(s)?', message=msgtxt)
        if answer:
            for kwiid in self.keywords.selection():
                c.execute("DELETE FROM search WHERE id = ? AND profile_id = ?", [kwiid,current_profile_id])
                conn.commit()
                self.refresh_keyword_tree()


    # Toggle Heartbeat Display in activity pane
    def toggle_view_hb(self):
        global settings
        if settings['hide_heartbeat'] == "1":
            c.execute("UPDATE setting SET value = '0' WHERE name = 'hide_heartbeat'")
            conn.commit()
            settings['hide_heartbeat'] = "0"
        else:
            c.execute("UPDATE setting SET value = '1' WHERE name = 'hide_heartbeat'")
            conn.commit()
            settings['hide_heartbeat'] = "1"
        self.refresh_activity_tree()


    # Toggle background scan setting for current profile
    def toggle_bg_scan(self):
        bg_setting = self.current_profile_scan.get()
        if bg_setting == 1:
            c.execute("UPDATE profile SET bgscan = 1 WHERE id = ?", [current_profile_id])
            conn.commit()
        else:
            c.execute("UPDATE profile SET bgscan = 0 WHERE id = ?", [current_profile_id])
            conn.commit()
        self.refresh_keyword_tree()


    # Export activity log for current profile
    def proc_exportlog(self):
        global current_profile_id
        c.execute("SELECT * FROM profile WHERE id = ? LIMIT 1",[current_profile_id])
        profile_record = c.fetchone()

        self.top = Toplevel(self)
        self.top.title("Export "+profile_record[1]+" Activity")
        self.top.geometry('650x500')

        self.exportmark = ttk.Label(self.top, text="Tab-delimited export for profile:"+profile_record[1], font=("10"))
        self.exportmark.pack(side=TOP, anchor=NW, padx=10, pady=10)

        # save and copy buttons
        tlframe = ttk.Frame(self.top)
        tlframe.pack(side=BOTTOM, anchor=SW, padx=10, pady=(0,10))
        self.copy_button = ttk.Button(tlframe, text = 'Copy All', command = self.export_copy_all)
        self.copy_button.pack(side=LEFT, padx=(0,10))
        self.saveas_button = ttk.Button(tlframe, text = 'Save As', command = self.export_saveas_popup)
        self.saveas_button.pack(side=RIGHT)

        # Text window
        self.export_text = Text(self.top, wrap=NONE)
        export_scrollbar = ttk.Scrollbar(self.top)
        export_scrollbar.pack(side=RIGHT, fill='y', padx=(0,10), pady=(0,10))
        export_scrollbar.config(command=self.export_text.yview)
        self.export_text.pack(side=LEFT, expand=True, fill='both', padx=(10,0), pady=(0,10))

        # right-click action
        self.rcmenu = Menu(self.top, tearoff = 0)
        self.rcmenu.add_command(label = 'Copy')
        self.export_text.bind('<Button-3>', lambda ev: self.export_copy_popup(ev))

        c.execute("SELECT * FROM activity WHERE profile_id = ? ORDER BY spotdate DESC",[current_profile_id])
        export_activity_records = c.fetchall()

        for record in export_activity_records:
            insert_rec = record[7]+"\t"+record[2]+"\t"+record[3]+"\t"+record[4]+"\t"+record[5]+"\t"+record[6]+"\n"
            self.export_text.insert(tk.END, insert_rec)

        self.top.focus()
        self.top.grab_set()
        self.top.bind('<Escape>', lambda x: self.top.destroy())


    # export saveas
    def export_saveas_popup(self):
        fname = fd.asksaveasfilename(defaultextension=".txt")
        if fname is None or fname == '':
            return
        saveas_text = str(self.export_text.get('1.0', 'end'))
        with open(fname,mode='w',encoding='utf-8') as f:
            f.write(saveas_text)
            f.close()


    # export copy button
    def export_copy_all(self):
        self.clipboard_clear()
        text = self.export_text.get('1.0', 'end')
        self.clipboard_append(text)
        self.copy_button.configure(text="Copied")


    # export right-click copy action
    def export_copy_popup(self, ev):
        self.rcmenu.tk_popup(ev.x_root,ev.y_root)
        self.clipboard_clear()
        text = self.export_text.get('sel.first', 'sel.last')
        self.clipboard_append(text)


    # Delete profile activity log entries
    def proc_dellog(self):
        global current_profile_id

        c.execute("SELECT * FROM profile WHERE id = ? LIMIT 1",[current_profile_id])
        profile_record = c.fetchone()

        msgtxt = "Are you sure you want to remove all activity for the "+profile_record[1]+" profile? This action cannot be undone."
        answer = askyesno(title='Clear Log?', message=msgtxt)
        if answer:
            # delete associated activity logs from the database
            c.execute("DELETE FROM activity WHERE profile_id = ?", [current_profile_id])
            conn.commit()
            # refresh log treeview
            self.refresh_activity_tree()


    # View activity from main window
    def view_activity(self, ev):
        aciid = int(self.activity.focus())
        c.execute("SELECT * FROM activity WHERE id = ?",[aciid])
        activity = c.fetchone()
        messagebox.showinfo("Activity Detail",activity)


    # View activity details by type, from search term detail window
    def view_activity_type(self, rxtype):
        if rxtype=="act":
            aciid = int(self.top.activity.focus())
        if rxtype=="dir":
            aciid = int(self.top.directed.focus())
        if rxtype=="spot":
            aciid = int(self.top.spot.focus())

        c.execute("SELECT * FROM activity WHERE id = ?",[aciid])
        activity = c.fetchone()
        messagebox.showinfo("Activity Detail",activity)


    # View search term detail window, divided by type
    def view_keyword_activity(self, ev):
        if not self.keywords.focus():
            return
        kwiid = int(self.keywords.focus())
        c.execute("SELECT * FROM search WHERE id = ?",[kwiid])
        search = c.fetchone()

        self.top = Toplevel(self)
        self.top.title("Search Term Activity")
        self.top.geometry('440x700')
        self.top.resizable(width=False, height=False)

        kwvals = self.keywords.item(kwiid)
        msgtxt = kwvals['values'][0]+" Activity"

        self.top.activitymark = ttk.Label(self.top, text=msgtxt, font=("14"))
        self.top.activitymark.grid(row=0, column = 0, sticky="W", padx=10)

        # RX.ACTIVITY treeview
        self.top.activitymark = ttk.Label(self.top, text="RX.ACTIVITY", font=("12"))
        self.top.activitymark.grid(row=1, column = 0, sticky="W", padx=10)

        self.top.activity = ttk.Treeview(self.top, show='headings', selectmode="browse", height="6")
        self.top.activity["columns"]=("value","stamp")

        self.top.activity.column("value", width=240, minwidth=240)
        self.top.activity.column("stamp", width=120, minwidth=120, stretch=0)

        self.top.activity.heading('value', text='Activity')
        self.top.activity.heading('stamp', text='When')

        self.top.activity.bind('<Double-1>', lambda x: self.view_activity_type("act"))
        self.top.activity.grid(row=2, column = 0, sticky='NSEW', padx=(10,0), pady=(0,10))
        self.top.acscrollbar = ttk.Scrollbar(self.top, orient=tk.VERTICAL, command=self.top.activity.yview)
        self.top.activity.configure(yscroll=self.top.acscrollbar.set)
        self.top.acscrollbar.grid(row=2, column=1, sticky='NSEW', padx=(0,10), pady=(0,10))

        sql = "SELECT * FROM activity WHERE profile_id = ? AND type = ? AND (call LIKE ? OR value LIKE ?) ORDER BY spotdate DESC"
        c.execute(sql,[current_profile_id,"RX.ACTIVITY",'%'+search[2]+'%','%'+search[2]+'%'])
        tactivity_records = c.fetchall()

        count=0
        for record in tactivity_records:
            if count % 2 == 0:
                self.top.activity.insert('', tk.END, iid=record[0], values=(record[3],record[7]), tags=('oddrow'))
            else:
                self.top.activity.insert('', tk.END, iid=record[0], values=(record[3],record[7]), tags=('evenrow'))
            count+=1

        # RX.DIRECTED treeview
        self.top.directedmark = ttk.Label(self.top, text="RX.DIRECTED", font=("12"))
        self.top.directedmark.grid(row=3, column = 0, sticky="W", padx=10)

        self.top.directed = ttk.Treeview(self.top, show='headings', selectmode="browse", height="6")
        self.top.directed["columns"]=("value","stamp")

        self.top.directed.column("value", width=240, minwidth=240)
        self.top.directed.column("stamp", width=120, minwidth=120, stretch=0)

        self.top.directed.heading('value', text='Directed')
        self.top.directed.heading('stamp', text='When')

        self.top.directed.bind('<Double-1>', lambda x: self.view_activity_type("dir"))
        self.top.directed.grid(row=4, column=0, sticky=NSEW, padx=(10,0), pady=(0,10))
        self.top.acscrollbar = ttk.Scrollbar(self.top, orient=tk.VERTICAL, command=self.top.directed.yview)
        self.top.directed.configure(yscroll=self.top.acscrollbar.set)
        self.top.acscrollbar.grid(row=4, column=1, sticky=NS, padx=(0,10), pady=(0,10))

        sql = "SELECT * FROM activity WHERE profile_id = ? AND type = ? AND (call LIKE ? OR value LIKE ?) ORDER BY spotdate DESC"
        c.execute(sql,[current_profile_id,"RX.DIRECTED",'%'+search[2]+'%','%'+search[2]+'%'])
        dactivity_records = c.fetchall()

        count=0
        for record in dactivity_records:
            if count % 2 == 0:
                self.top.directed.insert('', tk.END, iid=record[0], values=(record[3],record[7]), tags=('oddrow'))
            else:
                self.top.directed.insert('', tk.END, iid=record[0], values=(record[3],record[7]), tags=('evenrow'))
            count+=1

        # RX.DIRECTED treeview
        self.top.spotmark = ttk.Label(self.top, text="RX.SPOT", font=("12"))
        self.top.spotmark.grid(row=5, column = 0, sticky="W", padx=10)

        self.top.spot = ttk.Treeview(self.top, show='headings', selectmode="browse", height="6")
        self.top.spot["columns"]=("snr","call","stamp")

        self.top.spot.column("snr", width=60, minwidth=60)
        self.top.spot.column("call", width=180, minwidth=180)
        self.top.spot.column("stamp", width=120, minwidth=120, stretch=0)

        self.top.spot.heading('snr', text='SNR')
        self.top.spot.heading('call', text='Call')
        self.top.spot.heading('stamp', text='When')

        self.top.spot.bind('<Double-1>', lambda x: self.view_activity_type("spot"))
        self.top.spot.grid(row=6, column=0, sticky=NSEW, padx=(10,0), pady=(0,10))
        self.top.acscrollbar = ttk.Scrollbar(self.top, orient=tk.VERTICAL, command=self.top.spot.yview)
        self.top.spot.configure(yscroll=self.top.acscrollbar.set)
        self.top.acscrollbar.grid(row=6, column=1, sticky=NS, padx=(0,10), pady=(0,10))

        sql = "SELECT * FROM activity WHERE profile_id = ? AND type = ? AND (call LIKE ? OR value LIKE ?) ORDER BY spotdate DESC"
        c.execute(sql,[current_profile_id,"RX.SPOT",'%'+search[2]+'%','%'+search[2]+'%'])
        sactivity_records = c.fetchall()

        count=0
        for record in sactivity_records:
            if count % 2 == 0:
                self.top.spot.insert('', tk.END, iid=record[0], values=(record[5],record[6],record[7]), tags=('oddrow'))
            else:
                self.top.spot.insert('', tk.END, iid=record[0], values=(record[5],record[6],record[7]), tags=('evenrow'))
            count+=1

        # set colors based on theme
        if settings['dark_theme']=='1':
            self.top.activity.tag_configure('oddrow', background='#777')
            self.top.activity.tag_configure('evenrow', background='#555')
            self.top.directed.tag_configure('oddrow', background='#777')
            self.top.directed.tag_configure('evenrow', background='#555')
            self.top.spot.tag_configure('oddrow', background='#777')
            self.top.spot.tag_configure('evenrow', background='#555')
        else:
            self.top.activity.tag_configure('oddrow', background='#FFF')
            self.top.activity.tag_configure('evenrow', background='#EEE')
            self.top.directed.tag_configure('oddrow', background='#FFF')
            self.top.directed.tag_configure('evenrow', background='#EEE')
            self.top.spot.tag_configure('oddrow', background='#FFF')
            self.top.spot.tag_configure('evenrow', background='#EEE')

        self.top.focus()
        self.top.grab_set()
        self.top.bind('<Escape>', lambda x: self.top.destroy())


    # Refresh main window keyword tree
    def refresh_keyword_tree(self):
        global search_strings, bgsearch_strings
        # preserve focus after refresh
        kwiid=0
        if self.keywords.focus():
            kwiid = int(self.keywords.focus())

        # clear out and rebuild
        for entry in self.keywords.get_children():
            self.keywords.delete(entry)
        search_strings.clear()
        bgsearch_strings.clear()

        # we will need to know which profiles have background scan enabled
        c.execute("SELECT id FROM profile WHERE bgscan = '1'")
        profile_bgscan = c.fetchall()

        bgscans=[]
        for prof in profile_bgscan:
            bgscans.append(prof[0])

        c.execute("SELECT * FROM search ORDER BY last_seen DESC")
        search_records = c.fetchall()

        count=0
        for record in search_records:
            if record[1] == current_profile_id:
                if count % 2 == 0:
                    self.keywords.insert('', tk.END, iid=record[0], values=(record[2],record[3]), tags=('oddrow'))
                else:
                    self.keywords.insert('', tk.END, iid=record[0], values=(record[2],record[3]), tags=('evenrow'))
                count+=1
                search_strings.append(record[2])
            else:
                # check if profile in question has background scan enabled
                if record[1] in bgscans:
                    bgsearch_strings[record[2]]=record[1]


        # restore focus
        if kwiid>0:
            if self.keywords.exists(kwiid) == True:
                self.keywords.focus(kwiid)
                self.keywords.selection_set(kwiid)


    # Refresh main window activity tree
    def refresh_activity_tree(self):
        global settings
        # preserve focus after refresh
        aciid=0
        if self.activity.focus():
            aciid = int(self.activity.focus())

        for entry in self.activity.get_children():
            self.activity.delete(entry)

        if settings['hide_heartbeat']=="1":
            c.execute("SELECT * FROM activity WHERE profile_id = ? AND value NOT LIKE '%HB%' AND value NOT LIKE '%HEARTBEAT%' ORDER BY spotdate DESC LIMIT 100",[current_profile_id])
            self.activitymark.config(text = "Matched Activity (last 100 -HB)")
            self.viewmenu.entryconfigure(0, label="\u2713 Hide Heartbeats")
        else:
            c.execute("SELECT * FROM activity WHERE profile_id = ? ORDER BY spotdate DESC LIMIT 100",[current_profile_id])
            self.activitymark.config(text = "Matched Activity (last 100)")
            self.viewmenu.entryconfigure(0, label="Hide Heartbeats")
        activity_records = c.fetchall()

        count=0
        for record in activity_records:
            # use CALL if ACTIVITY is blank (RX.SPOT)
            act=record[3]
            if act=="":
                act=record[6]

            if count % 2 == 0:
                self.activity.insert('', tk.END, iid=record[0], values=(record[2],act,record[7]), tags=('oddrow'))
            else:
                self.activity.insert('', tk.END, iid=record[0], values=(record[2],act,record[7]), tags=('evenrow'))
            count+=1

        if aciid>0:
            if self.activity.exists(aciid) == True:
                self.activity.focus(aciid)
                self.activity.selection_set(aciid)


    # Build/rebuild profile sub-menu from database
    def build_profilemenu(self):
        global current_profile_id
        # first, remove any entries that exist in sub-menu
        if self.profilemenu.winfo_exists():
            if self.profilemenu.index('end') is not None:
                self.profilemenu.delete(0,self.profilemenu.index('end'))

        # also remove all from combobox
        self.profilecombo.delete(0, tk.END)

        # next, rebuild from database
        c.execute("SELECT * FROM profile")
        profile_records = c.fetchall()
        comboopts = []

        for record in profile_records:
            comboopts.append(record[1])

            if record[2] == 1:
                seltext = " *"
                current_profile_id = record[0]
                combosel = record[1]
                bgscanbox = record[3]
            else:
                seltext = ""
            self.profilemenu.add_command(label = record[1]+seltext, command = lambda profileid=record[0]: self.profile_select(profileid))

        # update bgscan checkbox based on current visible profile setting
        if bgscanbox == 1:
            self.current_profile_scan.set(1)
        else:
            self.current_profile_scan.set(0)

        self.profilecombo['values'] = comboopts
        self.profilecombo.set(combosel)
        self.update()


    # Select a profile
    def profile_select(self, profileid):
        c.execute("UPDATE profile SET def = 0")
        c.execute("UPDATE profile SET def = 1 WHERE id = ?", [profileid])
        conn.commit()
        self.build_profilemenu()
        self.refresh_keyword_tree()
        self.refresh_activity_tree()


    # select a profile through the combobox
    def profile_sel_combo(self, ev):
        # note that profile titles are a unique key in the database
        # so they're safe to match on
        profile_title = self.profilecombo.get()
        c.execute("UPDATE profile SET def = 0")
        c.execute("UPDATE profile SET def = 1 WHERE title = ?", [profile_title])
        conn.commit()
        self.build_profilemenu()
        self.refresh_keyword_tree()
        self.refresh_activity_tree()


    # Add new profile
    def menu_new(self):
        self.top = Toplevel(self)
        self.top.title("New Profile")
        self.top.resizable(width=False, height=False)

        label_new = ttk.Label(self.top, text = "New Profile Name")
        label_new.grid(row = 0, column = 0, padx=(10,0), pady=(20,0))
        self.new_profile = ttk.Entry(self.top)
        self.new_profile.grid(row = 0, column = 1, padx=(0,10), pady=(20,0))
        self.new_profile.bind("<Return>", lambda x: self.proc_new())

        cbframe = ttk.Frame(self.top)
        cbframe.grid(row=2, columnspan=2, sticky=NSEW, padx=10)

        create_button = ttk.Button(cbframe, text = "Create", command = self.proc_new)
        create_button.grid(row=0, column = 0, padx=(60,10), pady=(20,20))
        cancel_button = ttk.Button(cbframe, text = "Cancel", command = self.top.destroy)
        cancel_button.grid(row=0, column = 1, pady=(20,20))

        self.top.grab_set()
        self.new_profile.focus()
        self.top.bind('<Escape>', lambda x: self.top.destroy())


    # Process new profile
    def proc_new(self):
        new_val = self.new_profile.get()
        if new_val == "":
            return
        c.execute("INSERT INTO profile(title,def,bgscan) VALUES (?,?,?)", [new_val,0,0])
        conn.commit()
        self.build_profilemenu()
        self.top.destroy()


    # Edit existing profile
    def menu_edit(self):
        global current_profile_id
        c.execute("SELECT * FROM profile WHERE id = ? LIMIT 1",[current_profile_id])
        profile_record = c.fetchone()

        self.top = Toplevel(self)
        self.top.title("Edit Profile")
        self.top.resizable(width=False, height=False)

        label_edit = ttk.Label(self.top, text = "Edit Profile Name")
        label_edit.grid(row = 0, column = 0, padx=(10,0), pady=(20,0))
        self.edit_profile = ttk.Entry(self.top)
        self.edit_profile.insert(0, profile_record[1])
        self.edit_profile.grid(row = 0, column = 1, padx=(0,10), pady=(20,0))
        self.edit_profile.bind("<Return>", lambda x: self.proc_edit())

        cbframe = ttk.Frame(self.top)
        cbframe.grid(row=2, columnspan=2, sticky=NSEW, padx=10)

        save_button = ttk.Button(cbframe, text = "Save", command = self.proc_edit)
        save_button.grid(row=0, column = 0, padx=(60,20), pady=(20,20))
        cancel_button = ttk.Button(cbframe, text = "Cancel", command = self.top.destroy)
        cancel_button.grid(row=0, column = 1, pady=(20,20))

        self.top.grab_set()
        self.edit_profile.focus()
        self.top.bind('<Escape>', lambda x: self.top.destroy())


    # Process profile edit
    def proc_edit(self):
        global current_profile_id
        new_val = self.edit_profile.get()
        if new_val == "":
            return
        c.execute("UPDATE profile SET title = ? WHERE id = ?", [new_val, current_profile_id])
        conn.commit()
        self.build_profilemenu()
        self.top.destroy()


    # Delete the current selected profile
    def menu_remove(self):
        global current_profile_id

        # make sure we're not deleting the last remaining profile
        c.execute("SELECT Count() FROM profile")
        profile_count = c.fetchone()[0]

        if profile_count < 2:
            messagebox.showwarning("Error Removing Profile","Unable to remove selected profile, because it is the last remaining profile. At least one profile must be configured.")
            return

        c.execute("SELECT * FROM profile WHERE id = ? LIMIT 1",[current_profile_id])
        profile_record = c.fetchone()

        msgtxt = "Are you sure you want to remove the profile named "+profile_record[1]+" and all associated activity? This action cannot be undone."
        answer = askyesno(title='Remove Profile?', message=msgtxt)
        if answer:
            # delete the profile from the database
            c.execute("DELETE FROM profile WHERE id = ?", [current_profile_id])
            conn.commit()
            # delete associated activity logs from the database
            c.execute("DELETE FROM activity WHERE profile_id = ?", [current_profile_id])
            conn.commit()
            # delete associated keywords from the database
            c.execute("DELETE FROM search WHERE profile_id = ?", [current_profile_id])
            conn.commit()
            # reset the default profile
            c.execute("UPDATE profile SET def = 1 WHERE rowid = (SELECT MIN(rowid) FROM profile)")
            conn.commit()
            current_profile_id = 0
            self.build_profilemenu()
            
    def update_network(self):
        self.top = Toplevel(self)
        self.top.title("Network Settings")
        self.top.geometry('800x300')
        
        ## force a re-read of the setting table
        c.execute("SELECT * FROM setting")
        dbsettings = c.fetchall()
        settings = {}
        for setting in dbsettings:
            settings[setting[1]]=setting[2]
        
        new_settings = settings.copy()
            
        ## Let's assign the TCP/UDP variables from the settings{}
        dtRow = 0
        label_col = 0
        entry_col = 1
        label2_col = 2
        entry2_col = 3
        label_padx = 8
        
        saveButton = Button(self.top, text="Update Configuration", command=lambda:self.saveData(new_settings))
        saveButton.grid(column=label_col,row=dtRow, sticky = "w")
        saveButton.configure(bg="blue", fg="white")
        
        cancel_button = ttk.Button(self.top, text = "Cancel", command = self.top.destroy)
        cancel_button.grid(row=dtRow, column = label2_col, padx=(20,20))
        
        blankRow = dtRow+1
        blankLabel = Label(self.top)
        blankLabel.config(text = '         ')
        blankLabel.grid(column=label_col,row=blankRow, sticky="w")
        
        tcpRow = dtRow+2
        tcp_addr_label = Label(self.top, text="TCP Address: ")
        tcp_addr_label.grid(column=label_col, row=tcpRow, sticky="e", padx = label_padx)
        
        ### Because we are using a 'toplevel' window, we reference the widget
        ### instead of a StringVar()
        self.tcp_addr_entry = Entry(self.top)
        self.tcp_addr_entry.grid(column=entry_col, row=tcpRow, sticky='w')
        self.tcp_addr_entry.delete(0,END)
        self.tcp_addr_entry.insert(0,settings["tcp_ip"])
                
        tcp_port_label = Label(self.top, text="TCP Port: ")
        tcp_port_label.grid(column=label2_col, row=tcpRow, sticky="e", padx = label_padx)

        self.tcp_port_entry = Entry(self.top)
        self.tcp_port_entry.grid(column=entry2_col, row=tcpRow, sticky='w')
        self.tcp_port_entry.delete(0,END)
        self.tcp_port_entry.insert(0,settings["tcp_port"])
        
        blank2Row = dtRow+3
        blank2Label = Label(self.top)
        blank2Label.config(text = '         ')
        blank2Label.grid(column=label_col,row=blank2Row, sticky="w")
        
        udpRow = dtRow+4
        udp_addr_label = Label(self.top, text="UDP Address: ")
        udp_addr_label.grid(column=label_col, row=udpRow, sticky="e", padx = label_padx)

        self.udp_addr_entry = Entry(self.top)
        self.udp_addr_entry.grid(column=entry_col, row=udpRow, sticky='w')
        self.udp_addr_entry.delete(0,END)
        self.udp_addr_entry.insert(0,settings["udp_ip"])
        
        udp_port_label = Label(self.top, text="UDP Port: ")
        udp_port_label.grid(column=label2_col, row=udpRow, sticky="e", padx = label_padx)

        self.udp_port_entry = Entry(self.top)
        self.udp_port_entry.grid(column=entry2_col, row=udpRow, sticky='w')
        self.udp_port_entry.delete(0,END)
        self.udp_port_entry.insert(0,settings["udp_port"])

        self.top.grab_set()
        self.top.bind('<Escape>', lambda x: self.top.destroy())

    def saveData(self,new_settings):
        
        ## get settings from Entry widgets, not StringVar()
        server_data_keys=['udp_ip','udp_port','tcp_ip','tcp_port']
        for key in server_data_keys:
            if key == 'udp_ip':
                new_settings[key] = self.udp_addr_entry.get()
            elif key == 'udp_port':
                new_settings[key] = self.udp_port_entry.get()
            elif key == 'tcp_ip':
                new_settings[key] = self.tcp_addr_entry.get()
            elif key == 'tcp_port':
                new_settings[key] = self.tcp_port_entry.get()

        
        ## remove the old settings
        c.execute("DELETE FROM setting;")
        conn.commit()

        ## build list in same order as SQL
        ## dictionary matching does not guarentee proper order of values
        value_list = []
        for key in new_settings.keys():
            if key == 'udp_ip':
                value_list.append(new_settings[key])
            elif key == 'udp_port':
                value_list.append(new_settings[key])
            elif key == 'tcp_ip':
                value_list.append(new_settings[key])
            elif key == 'tcp_port':
                value_list.append(new_settings[key])
            elif key == 'hide_heartbeat':
                value_list.append(new_settings[key])
            elif key == 'dark_theme':
                value_list.append(new_settings[key])

        ## re-insert new settings
        sql = "INSERT INTO setting(name,value) VALUES ('udp_ip',?),('udp_port',?),('tcp_ip',?),('tcp_port',?),('hide_heartbeat',?),('dark_theme',?)"
        c.execute(sql,value_list)
        conn.commit()
        

    # About screen
    def about(self):
        about_info = swname+" version "+swversion+"\n\n"
        about_info += "Open Source, MIT License\n\n"
        about_info += "Questions to Joe, KF7MIX"
        messagebox.showinfo("About "+swname,about_info)


    # Mainloop
    def mainloop(self, *args):
        super().mainloop(*args)
        # shut down receiver thread
        if self.receiver:
            self.receiver.stop()


    # Watch activity thread, update gui as needed
    def poll_activity(self):
        if event.is_set():
            self.refresh_activity_tree()
            self.refresh_keyword_tree()
            event.clear()
        super().after(2000,self.poll_activity)


    # Start receiver thread
    def start_receiving(self):
        self.receiver = TCP_RX(self.sock)
        self.receiver.start()


    # Stop receiver thread
    def stop_receiving(self):
        self.receiver.stop()
        self.receiver.join()
        self.receiver = None


    # Quite function
    def menu_bye(self):
        # close the recv thread, database, and program
        conn.close()
        if tcp_conn:
            self.stop_receiving()
        self.destroy()


def main():
    ### adding python check
    if sys.version_info < (3,8):
        messagebox.showwarning('Python version Error','Python version is not at the required 3.8 or higher')
        sys.exit()
    ### do we have a good connection to JS8Call
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print('settings: ',settings)
        if settings['tcp_ip'] == '':
            settings['tcp_ip'] = '127.0.0.1'
            settings['tcp_port'] = '2442'
        sock.connect((settings['tcp_ip'], int(settings['tcp_port'])))
        tcp_conn = True
    except ConnectionRefusedError:
        rw = tk.Tk()
        rw.overrideredirect(1)
        rw.withdraw()
        messagebox.showwarning('Connection Error','Is JS8Call running? Check TCP port number in JS8Call.')
        rw.destroy()
    app = App(sock)
    app.mainloop()


if __name__ == '__main__':
    main()

