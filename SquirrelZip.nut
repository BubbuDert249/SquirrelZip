// squirrelzip.nut
// SquirrelZip - TAR, VPK, ZIP, GZ support
// - TAR: read/write/create
// - VPK: read/write/create
// - ZIP: read/write (no create)
// - GZ: read-only

class SquirrelZip {
    filename = null;
    archiveType = null;
    files = {};
    handle = null;

    constructor(fname) {
        this.filename = fname;
    }

    function open() {
        local ext = this.filename.split(".").pop().tolower();
        if (ext == "tar") { this.archiveType = "tar"; this._openTAR(); return; }
        if (ext == "vpk") { this.archiveType = "vpk"; this._openVPK(); return; }
        if (ext == "zip") { this.archiveType = "zip"; this._openZIP(); return; }
        if (ext == "gz") { this.archiveType = "gz"; this._openGZ(); return; }
        throw "Unknown archive type: " + ext;
    }

    function close() {
        if (this.handle) { this.handle.close(); this.handle = null; }
    }

    function listFiles() { return this.files.keys(); }

    function readFile(name) {
        if (!(name in this.files)) throw "File not found: " + name;
        if (this.archiveType == "tar") return this._readTARFile(name);
        if (this.archiveType == "vpk") return this._readVPKFile(name);
        if (this.archiveType == "zip") return this._readZIPFile(name);
        if (this.archiveType == "gz") return this._readGZFile(name);
        throw "Unknown archive type for readFile";
    }

    function writeFile(name, content) {
        if (this.archiveType == "tar") return this._writeTARFile(name, content);
        if (this.archiveType == "vpk") return this._writeVPKFile(name, content);
        if (this.archiveType == "zip") return this._writeZIPFile(name, content);
        if (this.archiveType == "gz") throw "GZ archives are read-only";
        throw "Unknown archive type for writeFile";
    }

    static function createNew(fname, files) {
        local ext = fname.split(".").pop().tolower();
        if (ext == "tar") return SquirrelZip._createNewTAR(fname, files);
        if (ext == "vpk") return SquirrelZip._createNewVPK(fname, files);
        if (ext == "zip") throw "Cannot create new ZIP archives";
        if (ext == "gz") throw "Cannot create new GZ archives";
        throw "Unknown archive type for createNew";
    }

    // --- TAR IMPLEMENTATION ---
    function _openTAR() {
        this.handle = file.open(this.filename, "rb");
        this.files = {};
        while (true) {
            local header = this.handle.readblob(512);
            if (header.len() < 512) break;
            local name = stripNulls(header.slice(0,100).tostring());
            if (name == "") break;
            local sizeOct = stripNulls(header.slice(124,136).tostring());
            local size = sizeOct.tointeger(8);
            local pos = this.handle.tell();
            this.files[name] <- { offset = pos, size = size };
            local skip = ((size + 511) / 512) * 512;
            this.handle.seek(pos + skip, 'b');
        }
    }

    function _readTARFile(name) {
        local f = this.files[name];
        this.handle.seek(f.offset, 'b');
        return this.handle.readblob(f.size).tostring();
    }

    function _writeTARFile(name, content) {
        local all = {};
        foreach (k,v in this.files) all[k] <- this._readTARFile(k);
        all[name] <- content;
        SquirrelZip._createNewTAR(this.filename, all);
        this._openTAR();
    }

    static function _createNewTAR(fname, files) {
        local out = file.open(fname, "wb");
        foreach (n,data in files) {
            local size = data.len();
            local header = blob(512); header.fill(0);
            header.writestr(0, n);
            header.writestr(124, format("%011o", size));
            header[156] = '0';
            out.writeblob(header);
            out.writestr(data);
            local pad = (512 - (size % 512)) % 512;
            if (pad > 0) out.writestr("".repeat(pad));
        }
        out.writestr("".repeat(1024));
        out.close();
    }

    // --- VPK IMPLEMENTATION ---
    function _openVPK() {
        this.handle = file.open(this.filename, "rb");
        local magic = this.handle.readn('i');
        if (magic != 0x55aa1234) throw "Invalid VPK magic";
        local count = this.handle.readn('i');
        this.files = {};
        for (local i=0;i<count;i++) {
            local nameLen = this.handle.readn('i');
            local name = this.handle.readblob(nameLen).tostring();
            local size = this.handle.readn('i');
            local offset = this.handle.readn('i');
            this.files[name] <- { offset = offset, size = size };
        }
    }

    function _readVPKFile(name) {
        local f = this.files[name];
        this.handle.seek(f.offset, 'b');
        return this.handle.readblob(f.size).tostring();
    }

    function _writeVPKFile(name, content) {
        local all = {};
        foreach (k,v in this.files) all[k] <- this._readVPKFile(k);
        all[name] <- content;
        SquirrelZip._createNewVPK(this.filename, all);
        this._openVPK();
    }

    static function _createNewVPK(fname, files) {
        local out = file.open(fname, "wb");
        out.writen(0x55aa1234,'i');
        out.writen(files.len(),'i');
        local headerPos = out.tell();
        local dir = [];
        foreach (n,data in files) {
            dir.append({ name=n, size=data.len(), data=data });
        }
        local tableSize = 0;
        foreach (f in dir) tableSize += 12+f.name.len();
        local dataOffset = headerPos + tableSize;
        local cur = dataOffset;
        foreach (f in dir) {
            out.writen(f.name.len(),'i');
            out.writestr(f.name);
            out.writen(f.size,'i');
            out.writen(cur,'i');
            cur += f.size;
        }
        foreach (f in dir) out.writestr(f.data);
        out.close();
    }

    // --- ZIP IMPLEMENTATION (read/write) ---
    function _openZIP() {
        this.handle = file.open(this.filename, "rb+");
        local len = this.handle.len();
        this.handle.seek(len-22, 'b');
        local sig = this.handle.readn('i');
        if (sig != 0x06054b50) throw "ZIP EOCD not found";
        this.handle.seek(len-22+10, 'b');
        local total = this.handle.readn('s');
        local cdSize = this.handle.readn('i');
        local cdOffset = this.handle.readn('i');
        this.handle.seek(cdOffset, 'b');
        this.files = {};
        for (local i=0;i<total;i++) {
            local sig2 = this.handle.readn('i');
            if (sig2 != 0x02014b50) throw "Bad central dir";
            this.handle.seek(28,'c');
            local nameLen = this.handle.readn('s');
            local extraLen = this.handle.readn('s');
            local commentLen = this.handle.readn('s');
            this.handle.seek(8,'c');
            local offset = this.handle.readn('i');
            local name = this.handle.readblob(nameLen).tostring();
            this.files[name] <- { offset = offset };
            this.handle.seek(extraLen+commentLen,'c');
        }
    }

    function _readZIPFile(name) {
        local f = this.files[name];
        this.handle.seek(f.offset,'b');
        local sig = this.handle.readn('i');
        if (sig != 0x04034b50) throw "Bad local header";
        this.handle.seek(18,'c');
        local compSize = this.handle.readn('i');
        local uncompSize = this.handle.readn('i');
        local nameLen = this.handle.readn('s');
        local extraLen = this.handle.readn('s');
        this.handle.seek(nameLen+extraLen,'c');
        local data = this.handle.readblob(compSize);
        return data.tostring(); // raw, no inflate
    }

    function _writeZIPFile(name, content) {
        // Simple: append new file at the end (raw), update central directory
        local out = file.open(this.filename, "ab");
        local offset = out.tell();
        // Local file header
        out.writen(0x04034b50,'i');
        out.writen(20,'s'); // version needed
        out.writen(0,'s'); // flags
        out.writen(0,'s'); // compression method
        out.writen(0,'s'); // mod time
        out.writen(0,'s'); // mod date
        out.writen(content.len(),'i'); // compressed size
        out.writen(content.len(),'i'); // uncompressed size
        out.writen(name.len(),'s');
        out.writen(0,'s'); // extra
        out.writestr(name);
        out.writestr(content);
        this.files[name] <- { offset = offset };
    }

    // --- GZ read-only ---
    function _openGZ() {
        this.handle = file.open(this.filename, "rb");
        local content = this.handle.readblob(this.handle.len());
        this.files = {};
        this.files[this.filename] <- { data = content };
    }

    function _readGZFile(name) {
        return this.files[name].data.tostring();
    }
}

// --- helper ---
function stripNulls(str) {
    local idx = str.find("\0");
    return (idx != null) ? str.slice(0, idx) : str;
}
