# JS8Spotter InitDB v0.4a - 1/20/2022
# Utility to initialize database
#
# MIT License, Copyright 2022 Joseph D Lyman KF7MIX
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

import sqlite3
### adding check for pre-existing database - N4FWD
import os

base_dir = ""

def initialize_db():
    environment = set_environment()
    os.chdir(environment)
    ### 
    if os.path.exists('js8spotter.db'):
        ### do not re-init an existing database - N4FWD
        pass
    else:
        ## create a new database and initialize it - N4FWD
        with open('js8spotter.db',mode='w'):pass
        
        conn = sqlite3.connect('js8spotter.db')
        c = conn.cursor()

        c.execute("""CREATE TABLE setting (
            id    INTEGER PRIMARY KEY AUTOINCREMENT,
            name  TEXT    UNIQUE ON CONFLICT IGNORE,
            value TEXT
        )
        """)
        conn.commit()

        c.execute("""CREATE TABLE profile (
            id     INTEGER PRIMARY KEY AUTOINCREMENT,
            title  TEXT    UNIQUE ON CONFLICT IGNORE,
            def    BOOLEAN DEFAULT (0),
            bgscan BOOLEAN DEFAULT (0)
        )
        """)
        conn.commit()


        c.execute("""CREATE TABLE activity (
            id         INTEGER   PRIMARY KEY AUTOINCREMENT,
            profile_id INTEGER,
            type       TEXT,
            value      TEXT,
            dial       TEXT,
            snr        TEXT,
            call       TEXT,
            spotdate   TIMESTAMP
        )
        """)
        conn.commit()


        c.execute("""CREATE TABLE search (
            id         INTEGER   PRIMARY KEY AUTOINCREMENT,
            profile_id INT,
            keyword    TEXT,
            last_seen  TIMESTAMP
        )
        """)
        conn.commit()


        new_val = "Default"
        c.execute("INSERT INTO profile(title, def) VALUES ('Default', 1)")
        c.execute("INSERT INTO setting (name, value) VALUES ('udp_ip','127.0.0.1'),('udp_port','2242'),('tcp_ip','127.0.0.1'),('tcp_port','2442'),('hide_heartbeat',0),('dark_theme',0)")

        conn.commit()
        conn.close()
    return environment

def set_environment():
    ### Some code to accomodate the development environment
    ### leaving this in should not affect the production version
    js8spotter_dir = "JS8spotter"
    project_dir = os.getcwd()
    project_dir = project_dir[-8:]
    ### Is the program running in my development environment?
    if project_dir != "Projects":
        project_dir = "None"
    else:
        project_dir += "/js8spotter-support-files"
    
    ### Home Directory (known location)
    homeDir = os.path.expanduser('~')
    
    if project_dir == "None":
        base_dir = os.path.join(homeDir,js8spotter_dir)
    else:
        base_dir = os.path.join(homeDir,project_dir)
    
    try:
        os.mkdir(base_dir)
    except: ## directory already exists, do nothing
        pass
    
    return base_dir