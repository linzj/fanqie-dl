'use strict';
var mod = Process.findModuleByName('libmetasec_ml.so');
var base = mod.base;
console.log('SO_BASE=' + base);
console.log('PID=' + Process.id);

var tc = Memory.alloc(8);
Memory.protect(tc, 4096, 'rwx');
tc.writeU32(0xd53bd040); tc.add(4).writeU32(0xd65f03c0);
var readTpidr = new NativeFunction(tc, 'pointer', []);

function toHex(a){var b=new Uint8Array(a),h='';for(var i=0;i<b.length;i++)h+=('0'+b[i].toString(16)).slice(-2);return h;}
function sr(a,s){try{return a.readByteArray(s);}catch(e){return null;}}
function dp(l,a,s){if(a.isNull()){console.log(l+'=NULL');return;}var d=sr(a,s);if(d)console.log(l+'='+a+':'+toHex(d));else console.log(l+'='+a+':U');}

var ourTid=-1, vmN=0;

Interceptor.attach(base.add(0x26e684), {
    onEnter: function(a) {
        if (Process.getCurrentThreadId()!==ourTid) return;
        var tag=a[2].toInt32(), h=a[4];
        console.log('\nJNI tag=0x'+(tag>>>0).toString(16)+' h='+h);
        if (!h.isNull()) {
            console.log('TID='+ourTid+' TPIDR='+readTpidr());
            dp('HANDLE', h, 4096);
        }
    },
    onLeave: function(r) {
        if (Process.getCurrentThreadId()===ourTid) console.log('JNI_RET='+r);
    }
});

Interceptor.attach(base.add(0x168324), {
    onEnter: function(a) {
        if (Process.getCurrentThreadId()!==ourTid) return;
        vmN++;
        var bc=(a[0].sub(base).toInt32()>>>0);
        console.log('\nVM'+vmN+' bc=0x'+bc.toString(16)+' a2='+a[2]+' a3='+a[3]);
        dp('PK',a[1],48);
        if(!a[2].isNull()){for(var i=0;i<12;i++){try{dp('A'+i,a[2].add(i*8).readPointer(),512);}catch(e){}}}
        if(!a[3].isNull()){for(var i=0;i<12;i++){try{dp('B'+i,a[3].add(i*8).readPointer(),512);}catch(e){}}}
        dp('CB',a[4],48);
    },
    onLeave: function(r) {
        if (Process.getCurrentThreadId()===ourTid) console.log('VR'+vmN+'='+r);
    }
});

Java.perform(function(){
    var H=Java.use('java.util.HashMap');
    Java.enumerateClassLoaders({
        onMatch:function(l){try{l.findClass('ms.bd.c.r4');}catch(e){return;}
            Java.classFactory.loader=l;
            Java.choose('ms.bd.c.r4',{
                onMatch:function(i){
                    ourTid=Process.getCurrentThreadId();
                    console.log('OUR_TID='+ourTid);
                    var url='https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/detail/v1/?aid=1967&device_id=3722313718058683&_rticket='+Date.now()+'&book_id=7373660003258862617';
                    console.log('URL='+url);
                    var m=H.$new();
                    i.onCallToAddSecurityFactor(url,m);
                    ourTid=-1;
                    // read headers from result map
                    var it=m.entrySet().iterator();
                    while(it.hasNext()){var e=it.next();console.log('HDR '+e.getKey()+'='+e.getValue());}
                    console.log('DONE vm='+vmN);
                },
                onComplete:function(){}
            });
        },
        onComplete:function(){}
    });
});
