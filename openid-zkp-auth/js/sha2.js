
function split(jwt) {
    var header = jwt.split('.')[0];
    var payload = jwt.split('.')[1];

    var count = 0;
    for (var j = 0; j < Math.ceil(header.length / 64); j++) {
        tmp = header.slice(j * 64, (j + 1) * 64);
        console.log(Buffer.from(tmp, 'base64').toString())
        count++;
    }
    
    extra = (64 - (header.length % 64));
    if (header.length % 64 != 0) {
        tmp = payload.slice(0, extra);
        console.log(Buffer.from(tmp, 'base64').toString())
        count++;
    }

    len = payload.length - extra;
    offset = extra % 4;
    for (var j = 0; j < Math.ceil(len / 64); j++) {
        tmp = payload.slice(extra + (j * 64), extra + (j + 1) * 64);
        console.log(Buffer.from('0'.repeat(offset) + tmp, 'base64').toString())
        count++;
    }
}