var ips = []; 
const min = 0; 
const max = 128;

for (var i = min; i <= max; ++i) { 
    for (var y = 0; y < 256; ++y) { 
        ips.push(`82.221.${i}.${y}`);
    }
} 

console.log(ips.join(' '));