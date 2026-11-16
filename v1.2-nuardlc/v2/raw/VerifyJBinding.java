import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import net.sf.sevenzipjbinding.*;
import net.sf.sevenzipjbinding.impl.RandomAccessFileInStream;

class VerifyJBinding {
 static final String EXPECTED="96656cba9da615a4a8f103fc5ee2469c8fbd1a77d203561c251ad4c86840e0ae";
 public static void main(String[] args)throws Exception {
  SevenZip.initSevenZipFromPlatformJAR(null,new File(args[1]));
  MessageDigest hash=MessageDigest.getInstance("SHA-256");long[] count={0},last={System.nanoTime()};
  try(RandomAccessFile source=new RandomAccessFile(args[0],"r");IInArchive archive=SevenZip.openInArchive(null,new RandomAccessFileInStream(source))) {
   if(archive.getNumberOfItems()!=1)throw new IOException("Expected one APK entry");
   System.out.println("Format: "+archive.getArchiveFormat()+"; path: "+archive.getProperty(0,PropID.PATH)+"; size: "+archive.getProperty(0,PropID.SIZE));
   archive.extract(null,false,new IArchiveExtractCallback(){
    public ISequentialOutStream getStream(int index,ExtractAskMode mode)throws SevenZipException {
     if(index!=0 || mode!=ExtractAskMode.EXTRACT)throw new SevenZipException("Unexpected extraction request");
     return data->{hash.update(data);count[0]+=data.length;if(System.nanoTime()-last[0]>20_000_000_000L){System.out.println("Decoded "+count[0]+" bytes");last[0]=System.nanoTime();}return data.length;};
    }
    public void prepareOperation(ExtractAskMode mode){}
    public void setOperationResult(ExtractOperationResult result)throws SevenZipException {
     System.out.println("setOperationResult: "+result);
     if(result!=ExtractOperationResult.OK)throw new SevenZipException("Extraction failed: "+result);
    }
    public void setTotal(long total){}
    public void setCompleted(long completed){}
   });
  }
  String sum=HexFormat.of().formatHex(hash.digest());
  if(count[0]!=2285563072L || !sum.equals(EXPECTED))throw new IOException("Decoded APK mismatch: "+count[0]+" "+sum);
  String json="{\n  \"library\": \"SevenZipJBinding 16.02-2.01\",\n  \"platform\": \"Linux-amd64\",\n  \"extract_all_test_mode\": false,\n  \"result\": \"OK\",\n  \"apk_size\": "+count[0]+",\n  \"apk_sha256\": \""+sum+"\",\n  \"android_tested\": false\n}\n";
  Files.writeString(Path.of(args[2]),json);System.out.println(json);
 }
}
