import os
import base64
import bz2
import zipfile
import support as spt


## let's create a desktop launcher
def create_launcher(base_dir):
    ## Path to Desktop
    homeDir = os.path.expanduser('~')
    desktopDir = os.path.join(homeDir,"Desktop")
    launcher = "JS8spotter.desktop"
    desktop_launcher_path = os.path.join(desktopDir,launcher)
    ## get the path towhere js8msg2 is executing from
    exec_path = os.path.join(homeDir,"bin/js8spotter")
    icon_picture_path = os.path.join(base_dir,"js8spotter.png")
    ## updating launcher internals
    with open(desktop_launcher_path, "w") as fh:
        fh.write("[Desktop Entry]\n")
        fh.write("Version=1.0\n")
        fh.write("Type=Application\n")
        fh.write("Terminal=false\n")
        fh.write("Icon="+icon_picture_path+'\n')
        fh.write("Icon[en_US]="+icon_picture_path+'\n')
        fh.write("Name[en_US]=JS8spotter\n")
        fh.write("Exec="+exec_path+'\n')
        fh.write("Comment[en_US]=Tracking support for JS8call\n")
        fh.write("Name=JS8spotter\n")
        fh.write("Comment=Tracking support for JS8call\n")
    os.chmod(desktop_launcher_path,0o755)
    
def make_support(base_dir):
    ## recreate the zipfile containing the support files
    key = 'zipfile'
    files = {'zipfile':'support_files.zip'}
    fileName = os.path.join(base_dir,files[key])
    stringData = spt.support_array[key]
    byteData = bytes(stringData,'utf-8')
    decodedData = base64.b64decode(byteData)
    rawArray = bz2.decompress(decodedData)
    with open(fileName,"wb") as f:
            f.write(rawArray)
    ## unpack zipfile
    with zipfile.ZipFile(fileName, 'r') as zip_ref:
        zip_ref.extractall(base_dir)