import java.io.*;
import java.nio.*;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import com.android.apksig.KeyConfig;
import com.android.apksig.apk.ApkUtils;
import com.android.apksig.internal.apk.ApkSigningBlockUtils;
import com.android.apksig.internal.apk.v2.V2SchemeSigner;
import com.android.apksig.internal.apk.v3.V3SchemeSigner;
import com.android.apksig.internal.util.Pair;
import com.android.apksig.util.*;

/** Sign the existing APK body without moving any local ZIP record. */
class PreserveLayoutSign {
  static ApkSigningBlockUtils.SignerConfig signer(PrivateKey key,List<X509Certificate> certs,int min) throws Exception {
    var c=new ApkSigningBlockUtils.SignerConfig();
    c.privateKey=key;c.keyConfig=new KeyConfig.Jca(key);c.certificates=certs;
    c.minSdkVersion=min;c.maxSdkVersion=Integer.MAX_VALUE;
    c.signatureAlgorithms=V2SchemeSigner.getSuggestedSignatureAlgorithms(certs.get(0).getPublicKey(),min,false,false);
    return c;
  }
  public static void main(String[] args) throws Exception {
    if(args.length!=5)throw new IllegalArgumentException("input output keystore password-file alias");
    Path input=Path.of(args[0]),output=Path.of(args[1]);
    if(input.toAbsolutePath().normalize().equals(output.toAbsolutePath().normalize()))throw new IllegalArgumentException("Distinct paths required");
    char[] password=Files.readString(Path.of(args[3])).strip().toCharArray();
    KeyStore store=KeyStore.getInstance("PKCS12");
    try(InputStream stream=Files.newInputStream(Path.of(args[2]))){store.load(stream,password);}
    PrivateKey key=(PrivateKey)store.getKey(args[4],password);Arrays.fill(password,'\0');
    List<X509Certificate> certs=new ArrayList<>();
    for(var c:store.getCertificateChain(args[4]))certs.add((X509Certificate)c);
    try(RandomAccessFile source=new RandomAccessFile(input.toFile(),"r")) {
      DataSource all=DataSources.asDataSource(source);var sections=ApkUtils.findZipSections(all);
      long start=ApkUtils.findApkSigningBlock(all,sections).getStartOffset();
      ByteBuffer old=all.getByteBuffer(sections.getZipCentralDirectoryOffset(),Math.toIntExact(sections.getZipCentralDirectorySizeBytes())).order(ByteOrder.LITTLE_ENDIAN);
      ByteArrayOutputStream central=new ByteArrayOutputStream();int count=0;
      while(old.hasRemaining()) {
        int at=old.position();if(old.getInt(at)!=0x02014b50)throw new IOException("Central directory signature");
        int n=Short.toUnsignedInt(old.getShort(at+28)),x=Short.toUnsignedInt(old.getShort(at+30)),comment=Short.toUnsignedInt(old.getShort(at+32));
        int length=46+n+x+comment;byte[] name=new byte[n];old.position(at+46);old.get(name);
        byte[] record=new byte[length];old.position(at);old.get(record);
        central.write(record);count++;
      }
      byte[] directory=central.toByteArray();
      ByteBuffer eocd=ByteBuffer.allocate(sections.getZipEndOfCentralDirectory().remaining()).order(ByteOrder.LITTLE_ENDIAN);eocd.put(sections.getZipEndOfCentralDirectory().duplicate()).flip();
      eocd.putShort(8,(short)count);eocd.putShort(10,(short)count);eocd.putInt(12,directory.length);
      ApkUtils.setZipEocdCentralDirectoryOffset(eocd,start);
      DataSource body=all.slice(0,start),cd=DataSources.asDataSource(ByteBuffer.wrap(directory)),end=DataSources.asDataSource(eocd.duplicate());
      var v2=V2SchemeSigner.generateApkSignatureSchemeV2Block(RunnablesExecutor.SINGLE_THREADED,body,cd,end,List.of(signer(key,certs,25)),true);
      var v3=V3SchemeSigner.generateApkSignatureSchemeV3Block(RunnablesExecutor.SINGLE_THREADED,body,cd,end,List.of(signer(key,certs,28)));
      byte[] block=ApkSigningBlockUtils.generateApkSigningBlock(List.of(v2.signingSchemeBlock,v3.signingSchemeBlock));
      ApkUtils.setZipEocdCentralDirectoryOffset(eocd,start+block.length);
      try(FileChannel out=FileChannel.open(output,StandardOpenOption.CREATE,StandardOpenOption.TRUNCATE_EXISTING,StandardOpenOption.WRITE)) {
        FileChannel in=source.getChannel();long position=0;
        while(position<start){long copied=in.transferTo(position,Math.min(start-position,32L*1024*1024),out);if(copied<=0)throw new IOException("No APK copy progress");position+=copied;}
        for(ByteBuffer value:List.of(ByteBuffer.wrap(block),ByteBuffer.wrap(directory),eocd.rewind()))while(value.hasRemaining())out.write(value);
        out.force(true);
      }
      System.out.println("Signed APK v2/v3; original local records preserved: "+count);
    }
  }
}
