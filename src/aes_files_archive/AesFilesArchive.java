package aes_files_archive;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Scanner;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import es.vocali.util.AESCrypt;

/**
 * 
 * @author Yoann TRITZ
 *
 * @param Source
 *            Path to origin file.
 * @param Directory
 *            Path to save file.
 * @param Password
 *            password of the aes file.
 * @param Mode
 *            Modes : e for encrypt, d for decrypt.
 */
public class AesFilesArchive {

	static final int BUFFER = 1024;

	private static final int AES_FILE_VERSION = 2;
	private static final String JAVA_7_VERSION = "1.7";
	private static final String JAVA_8_VERSION = "1.8";
	private static final String JRE7_PREFIX_RESSOURCE = "/jre7/";
	private static final String JRE8_PREFIX_RESSOURCE = "/jre8/";
	private static final String LOCAL_POLICY_FILE = "local_policy.jar";
	private static final String RECYCLEBIN__NAME = "$RECYCLE.BIN";
	private static final String SYSTEM_INFO_NAME = "System Volume Information";
	private static String tempZipFile;
	private static final String US_EXPORT_POLICY_FILE = "US_export_policy.jar";

	public static void main(String[] args) {
		if (args.length != 4) {
			System.err.println("Arguments invalides, lire la documentation.");
			exitWithPrompt(1);
		}

		// Check JCE files
		checkJceFiles();

		String sourceDir = args[0];
		String dest = args[1];
		String pwd = args[2];
		String mode = args[3];

		// Check destination is a file, not a directory
		if (Files.isDirectory(Paths.get(dest))) {
			System.err.println("La destination doit être un fichier précis, pas le repertoire.");
			exitWithPrompt(1);
		}

		// Initialize the crypto engine
		AESCrypt cryptEngine = null;
		try {
			cryptEngine = new AESCrypt(pwd);
		} catch (UnsupportedEncodingException | GeneralSecurityException exc) {
			exc.printStackTrace();
			exitWithPrompt(1);
		}

		// Decrypt mode
		if (mode.equals("d")) {
			try {
				cryptEngine.decrypt(sourceDir, dest);
			} catch (IOException | GeneralSecurityException exc) {
				exc.printStackTrace();
				exitWithPrompt(1);
			}
			System.out.println("Restauration terminée.");
			exitWithPrompt(0);
		} else if (!mode.equals("e")) {
			System.err.println("Mode invalide, lire la documentation.");
			exitWithPrompt(1);
		}

		tempZipFile = System.currentTimeMillis() + ".zip";
		String tempZipFileName = sourceDir + File.separator + tempZipFile;

		// Encrypt mode follow
		if (!Files.isDirectory(Paths.get(sourceDir))) {
			System.err.println("La source n'est pas un répertoire.");
			exitWithPrompt(1);
		}

		// Create ZIP file
		try {
			// In Windows separator is the escape character, protect it
			String[] path = dest.split("\\" + File.separator);
			String secureBackupName = path[path.length - 1];
			pack(Paths.get(sourceDir), Paths.get(tempZipFileName), secureBackupName);
		} catch (Exception exc) {
			exc.printStackTrace();
			exitWithPrompt(1);
		}

		try {
			// Encrypt the ZIP backup and delete it
			cryptEngine.encrypt(AES_FILE_VERSION, tempZipFileName, dest);
			Files.delete(Paths.get(tempZipFileName));

		} catch (IOException | GeneralSecurityException e) {
			e.printStackTrace();
			exitWithPrompt(1);
		}

		System.out.println("Sauvegarde terminée.");
		exitWithPrompt(0);
	}

	/**
	 * Check JAVA JCE files and overwrite them if needed according to JRE
	 * version.
	 */
	private static void checkJceFiles() {
		// Identify java version
		String prefix = null;
		if (System.getProperty("java.version").startsWith(JAVA_8_VERSION)) {
			prefix = JRE8_PREFIX_RESSOURCE;
		} else if (System.getProperty("java.version").startsWith(JAVA_7_VERSION)) {
			prefix = JRE7_PREFIX_RESSOURCE;
		} else {
			System.err.println("Version JAVA non supportée, uniquement les JRE 7 / 8.");
			exitWithPrompt(1);
		}

		String secuityDir = System.getProperty("java.home") + File.separator + "lib" + File.separator + "security";
		try {
			boolean overwrite = false;
			if (!getMD5Checksum(AesFilesArchive.class.getResourceAsStream(prefix + LOCAL_POLICY_FILE))
					.equals(getMD5Checksum(secuityDir + File.separator + LOCAL_POLICY_FILE))) {
				File localPolicyFile = new File(secuityDir + File.separator + LOCAL_POLICY_FILE);
				if (!localPolicyFile.canWrite()) {
					System.err.println("Ecriture impossible du fichier local JCE.");
					exitWithPrompt(1);
				} else {
					localPolicyFile.delete();
					saveFile(localPolicyFile, AesFilesArchive.class.getResourceAsStream(prefix + LOCAL_POLICY_FILE));
					overwrite = true;
				}
			}
			if (!getMD5Checksum(AesFilesArchive.class.getResourceAsStream(prefix + US_EXPORT_POLICY_FILE))
					.equals(getMD5Checksum(secuityDir + File.separator + US_EXPORT_POLICY_FILE))) {
				File exportPolicyFile = new File(secuityDir + File.separator + US_EXPORT_POLICY_FILE);
				if (!exportPolicyFile.canWrite()) {
					System.err.println("Ecriture impossible du fichier US export JCE.");
					exitWithPrompt(1);
				} else {
					exportPolicyFile.delete();
					saveFile(exportPolicyFile,
							AesFilesArchive.class.getResourceAsStream(prefix + US_EXPORT_POLICY_FILE));
					overwrite = true;
				}
			}

			if (overwrite) {
				System.err.println("Installation des fichiers JCE terminées, redémarrez le progamme pour sauvegarder.");
				exitWithPrompt(1);
			}
		} catch (IOException e1) {
			e1.printStackTrace();
			exitWithPrompt(1);
		} catch (Exception e) {
			e.printStackTrace();
			exitWithPrompt(1);
		}
	}

	/**
	 * Create the checkum control for an InputStream
	 * 
	 * @param fis
	 * @return
	 * @throws Exception
	 */
	private static byte[] createChecksum(InputStream fis) throws Exception {
		byte[] buffer = new byte[BUFFER];
		MessageDigest complete = MessageDigest.getInstance("MD5");
		int numRead;

		do {
			numRead = fis.read(buffer);
			if (numRead > 0) {
				complete.update(buffer, 0, numRead);
			}
		} while (numRead != -1);

		fis.close();
		return complete.digest();
	}

	/**
	 * Exit program with user input to let him read the result.
	 * 
	 * @param code
	 *            Error code returned.
	 */
	private static void exitWithPrompt(int code) {
		System.out.println("Appuyez sur entrée...");
		Scanner scanEntry = new Scanner(System.in);
		scanEntry.nextLine();
		scanEntry.close();
		System.exit(code);
	}

	/**
	 * Get the MD5 checksum of a file by its stream.
	 * 
	 * @param filename
	 * @return
	 * @throws Exception
	 */
	private static String getMD5Checksum(InputStream stream) throws Exception {
		byte[] b = createChecksum(stream);
		String result = "";

		for (int i = 0; i < b.length; i++) {
			result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
		}
		stream.close();
		return result;
	}

	/**
	 * Get the MD5 checksum of a file by its name.
	 * 
	 * @param filename
	 * @return
	 * @throws Exception
	 */
	private static String getMD5Checksum(String filename) throws Exception {
		FileInputStream stream = new FileInputStream(filename);
		byte[] b = createChecksum(stream);
		String result = "";

		for (int i = 0; i < b.length; i++) {
			result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
		}
		stream.close();
		return result;
	}

	/**
	 * Pack a folder into a ZIP file. Exclude system files.
	 * 
	 * @param folder
	 * @param zipFilePath
	 * @param backupName
	 *            Backup name to exclude previous backup from archive.
	 * @throws IOException
	 */
	private static void pack(final Path folder, final Path zipFilePath, final String backupName) throws IOException {
		try (FileOutputStream fos = new FileOutputStream(zipFilePath.toFile());
				ZipOutputStream zos = new ZipOutputStream(fos)) {
			Files.walkFileTree(folder, new SimpleFileVisitor<Path>() {
				@Override
				public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
					if (dir.toFile().getName().equals(RECYCLEBIN__NAME)
							|| dir.toFile().getName().equals(SYSTEM_INFO_NAME) || !dir.toFile().canRead()) {
						return FileVisitResult.SKIP_SUBTREE;
					}
					// zos.putNextEntry(new
					// ZipEntry(folder.relativize(dir).toString()));
					// zos.closeEntry();
					return FileVisitResult.CONTINUE;
				}

				@Override
				public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
					// Do not copy recycle bin, temp zip file or previous backup
					if (!file.toFile().getName().equals(backupName) && !file.toFile().getName().equals(RECYCLEBIN__NAME)
							&& !file.toFile().getName().equals(SYSTEM_INFO_NAME)
							&& !file.toFile().getName().equals(tempZipFile)) {
						zos.putNextEntry(new ZipEntry(folder.relativize(file).toString()));
						Files.copy(file, zos);
						zos.closeEntry();
					}
					return FileVisitResult.CONTINUE;
				}

				@Override
				public FileVisitResult visitFileFailed(Path file, IOException exc) {
					if (file.toFile().getName().equals(SYSTEM_INFO_NAME)) {
						// Do not throw IO exception
						System.err.println("Exporation impossible : " + file.getFileName());
					} else {
						exc.printStackTrace();
						exitWithPrompt(1);
					}
					return FileVisitResult.SKIP_SUBTREE;
				}
			});
		} catch (IOException exc) {
			exc.printStackTrace();
			exitWithPrompt(1);
		}
	}

	/**
	 * Copy an input stream file into a file.
	 * 
	 * @param file
	 * @param is
	 */
	private static void saveFile(File file, InputStream is) {
		try {
			FileOutputStream fos = new FileOutputStream(file);
			try {
				byte[] buf = new byte[BUFFER];
				int len;
				while ((len = is.read(buf)) >= 0) {
					fos.write(buf, 0, len);
				}
			} finally {
				fos.close();
			}
		} catch (IOException e) {
			e.printStackTrace();
			exitWithPrompt(1);
		}
	}
}
