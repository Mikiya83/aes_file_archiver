package aes_files_archive;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Scanner;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.crypto.Cipher;

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

	private static final int AES_KEY_STRENGTH = 256;
	private static final int AES_FILE_VERSION = 2;
	private static final String RECYCLEBIN__NAME = "$RECYCLE.BIN";
	private static final String SYSTEM_INFO_NAME = "System Volume Information";
	private static String tempZipFile;

	public static void main(String[] args) {
		if (args.length != 4) {
			System.err.println("Arguments invalides, lire la documentation.");
			exitWithPrompt(1);
		}

		// Check JCE mode
		checkJceMode();

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
	private static void checkJceMode() {
		try {
			// try the property after update 151
			Security.setProperty("crypto.policy", "unlimited");
			if (Cipher.getMaxAllowedKeyLength("AES") >= AES_KEY_STRENGTH) {
				System.err.println("Impossible d'initialiser JAVA JCE.");
				exitWithPrompt(1);
			}
		} catch (SecurityException exc) {
			// Cannot write permission, do not crash on it it can be normal, try
			// to override JCE file next
		} catch (NoSuchAlgorithmException e2) {
			System.err.println("Version JAVA non supportée, abscence de AES.");
			exitWithPrompt(1);
		}
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
}
