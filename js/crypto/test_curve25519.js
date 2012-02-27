test_curve25519 = function() {

this.e1k   = new Array(32);
this.e2k   = new Array(32);
this.e1e2k = new Array(32);
this.e2e1k = new Array(32);
this.e1    = [  3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ];
this.e2    = [  5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ];
this.k     = [  9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ];

this.doit = function(ek,e,k) {
  var i;

  //for (i = 0;i < 32;++i) console.log(e[i]); 
  //for (i = 0;i < 32;++i) console.log(k[i]);
  curve25519.crypto_scalarmult(ek,e,k);
  //for (i = 0;i < 32;++i) console.log(ek[i]); 
};

this.test = function(r){
  var loop;
  var limit = r || 10;
  var i;

  for (loop=0 ; loop < limit ; ++loop) {
    this.doit(this.e1k,this.e1,this.k);
    this.doit(this.e2e1k,this.e2,this.e1k);
    this.doit(this.e2k,this.e2,this.k);
    this.doit(this.e1e2k,this.e1,this.e2k);
    for (i = 0 ; i < 32 ; ++i) if (this.e1e2k[i] != this.e2e1k[i]) {
      console.log("test_curve25519 fail");                 
    }
    for (i = 0 ; i < 32 ; ++i) this.e1[i] ^= this.e2k[i];
    for (i = 0 ; i < 32 ; ++i) this.e2[i] ^= this.e1k[i];
    for (i = 0 ; i < 32 ; ++i) this.k[i]  ^= this.e1e2k[i];
  }
  console.log("test_curve25519 pass");
}   

};