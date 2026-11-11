import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.zip.ZipFile;

/** Verify the complete APK with Java's independent ZIP parser/Inflater. */
public class VerifyArchive {
    public static void main(String[] args) throws Exception {
        String expected = args.length > 1 ? args[1] : "1fdc769fc79852bb8ddfe768da5fb5009fd02e9d81085ad23087647667d65ce2";
        long expectedSize = args.length > 2 ? Long.parseLong(args[2]) : 2285567170L;
        try (ZipFile zip = new ZipFile(Path.of(args[0]).toFile())) {
            var entry = zip.getEntry("Zenin_Icon_Crack.apk");
            if (entry == null || entry.getSize() != expectedSize) throw new AssertionError("APK size");
            var digest = MessageDigest.getInstance("SHA-256");
            var crc = new java.util.zip.CRC32();
            long count = 0;
            byte[] block = new byte[1024 * 1024];
            try (var input = zip.getInputStream(entry)) {
                int n;
                while ((n = input.read(block)) != -1) {
                    digest.update(block, 0, n);
                    crc.update(block, 0, n);
                    count += n;
                }
            }
            String actual = HexFormat.of().formatHex(digest.digest());
            if (count != entry.getSize() || crc.getValue() != entry.getCrc() || !actual.equals(expected))
                throw new AssertionError("APK checksum mismatch");
            System.out.println("PASS: Java ZIP extraction, " + count + " bytes, SHA-256 " + actual);
        }
    }
}
