// 深入分析 r4 类的内部逻辑
// 目标：理解 frameSign 输出如何转换为 X-Gorgon/X-Argus/X-Ladon/X-Khronos/X-Helios/X-Medusa
Java.perform(function() {
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                loader.findClass("ms.bd.c.r4");
                Java.classFactory.loader = loader;
                console.log("[+] Classloader set");

                // 分析 r4 的超类和实现的接口
                var r4cls = Java.use("ms.bd.c.r4");
                var cls = r4cls.class;
                console.log("\n=== r4 class info ===");
                console.log("Superclass: " + cls.getSuperclass());
                var interfaces = cls.getInterfaces();
                for (var i = 0; i < interfaces.length; i++) {
                    console.log("Interface: " + interfaces[i].getName());
                    // 列出接口方法
                    var imethods = interfaces[i].getDeclaredMethods();
                    for (var j = 0; j < imethods.length; j++) {
                        console.log("  " + imethods[j]);
                    }
                }

                // 找出 r4 的所有方法（包括继承的）
                console.log("\n=== r4 all methods ===");
                var allMethods = cls.getMethods();
                for (var i = 0; i < allMethods.length; i++) {
                    var m = allMethods[i];
                    if (m.getDeclaringClass().getName().indexOf("Object") === -1) {
                        console.log("  " + m);
                    }
                }

                // 分析超类链
                console.log("\n=== Superclass chain ===");
                var sc = cls.getSuperclass();
                while (sc !== null && sc.getName() !== "java.lang.Object") {
                    console.log("  " + sc.getName());
                    var scMethods = sc.getDeclaredMethods();
                    for (var i = 0; i < scMethods.length; i++) {
                        console.log("    " + scMethods[i]);
                    }
                    var scFields = sc.getDeclaredFields();
                    for (var i = 0; i < scFields.length; i++) {
                        console.log("    field: " + scFields[i]);
                    }
                    sc = sc.getSuperclass();
                }

                // 分析签名转换逻辑
                // Hook frameSign 并 trace 后续调用
                console.log("\n=== Tracing sign flow ===");

                // 查找可能处理签名的相关类
                var relatedClasses = ["ms.bd.c.q4", "ms.bd.c.p4", "ms.bd.c.o4", "ms.bd.c.n4"];
                for (var i = 0; i < relatedClasses.length; i++) {
                    try {
                        var rcls = Java.use(relatedClasses[i]);
                        var rmethods = rcls.class.getDeclaredMethods();
                        if (rmethods.length > 0) {
                            console.log("\n" + relatedClasses[i] + ":");
                            for (var j = 0; j < rmethods.length; j++) {
                                console.log("  " + rmethods[j]);
                            }
                        }
                    } catch(e) {}
                }

                // 查找 signinfo -> header 转换的类
                // 搜索包含 "Gorgon" "Argus" "Ladon" 等字符串的类
                console.log("\n=== Searching for header name references ===");
                Java.enumerateLoadedClasses({
                    onMatch: function(name) {
                        if (name.indexOf("ms.bd.c") === 0 && name.length < 15) {
                            try {
                                var c = Java.use(name);
                                var fields = c.class.getDeclaredFields();
                                for (var i = 0; i < fields.length; i++) {
                                    fields[i].setAccessible(true);
                                    // 检查静态 String 字段
                                    if (fields[i].getType().getName() === "java.lang.String") {
                                        try {
                                            var val = fields[i].get(null);
                                            if (val !== null && (val.toString().indexOf("Gorgon") !== -1 ||
                                                val.toString().indexOf("Argus") !== -1 ||
                                                val.toString().indexOf("Ladon") !== -1 ||
                                                val.toString().indexOf("Helios") !== -1 ||
                                                val.toString().indexOf("Medusa") !== -1 ||
                                                val.toString().indexOf("signinfo") !== -1)) {
                                                console.log("  " + name + "." + fields[i].getName() + " = " + val);
                                            }
                                        } catch(e) {}
                                    }
                                }
                            } catch(e) {}
                        }
                    },
                    onComplete: function() {
                        console.log("[*] Class scan done");
                    }
                });

            } catch(e) {}
        },
        onComplete: function() {}
    });
});
