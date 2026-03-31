// Dump libmetasec_ml.so from memory, page by page, skipping unreadable pages
var moduleName = "libmetasec_ml.so";
var m = Process.findModuleByName(moduleName);

if (!m) {
    console.log("Module not found!");
} else {
    console.log("Module: " + m.name);
    console.log("Base: " + m.base);
    console.log("Size: " + m.size + " (" + (m.size / 1024 / 1024).toFixed(2) + " MB)");
    console.log("Path: " + m.path);

    // Enumerate memory ranges for this module
    var moduleRanges = m.enumerateRanges('r--');
    console.log("\nReadable ranges within module: " + moduleRanges.length);
    for (var i = 0; i < moduleRanges.length; i++) {
        var r = moduleRanges[i];
        var offset = r.base.sub(m.base).toInt32();
        console.log("  offset=0x" + offset.toString(16) + " size=0x" + r.size.toString(16) + " prot=" + r.protection);
    }

    // Dump page by page (4KB pages)
    var PAGE_SIZE = 4096;
    var totalPages = Math.ceil(m.size / PAGE_SIZE);
    var dumpedPages = 0;
    var skippedPages = 0;

    // Create a buffer filled with zeros for the full module size
    // We'll send chunks and reconstruct on the host
    console.log("\nDumping " + totalPages + " pages...");

    // Send metadata first
    send({type: "meta", base: m.base.toString(), size: m.size, name: m.name});

    for (var page = 0; page < totalPages; page++) {
        var addr = m.base.add(page * PAGE_SIZE);
        var readSize = Math.min(PAGE_SIZE, m.size - page * PAGE_SIZE);
        try {
            var data = addr.readByteArray(readSize);
            send({type: "page", offset: page * PAGE_SIZE, size: readSize}, data);
            dumpedPages++;
        } catch(e) {
            // Page not readable, send zeros
            send({type: "skip", offset: page * PAGE_SIZE, size: readSize});
            skippedPages++;
        }
    }

    console.log("\nDump complete: " + dumpedPages + " pages dumped, " + skippedPages + " pages skipped");
    console.log("Total dumped: " + (dumpedPages * PAGE_SIZE / 1024) + " KB");
}
