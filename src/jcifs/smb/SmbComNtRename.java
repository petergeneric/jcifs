package jcifs.smb;

import jcifs.util.Hexdump;

/**
 * See <a href="http://msdn.microsoft.com/en-us/library/ee918023">SMB_COM_NT_RENAME Request on MSDN</a>
 */
class SmbComNtRename extends ServerMessageBlock
{
	/**
	 * Create a hard link to the original file.
	 */
	public static final int SMB_NT_RENAME_SET_LINK_INFO = 0x0103;

	/**
	 * An in-place rename of the file.&lt;122&gt;
	 */
	public static final int SMB_NT_RENAME_RENAME_FILE = 0x0104;

	/**
	 * Move the file within the path hierarchy. This information level is obsolete. Clients MUST NOT use this value in a
	 * request.&lt;123&gt;
	 */
	public static final int SMB_NT_RENAME_MOVE_FILE = 0x0105;

	private int searchAttributes;
	private int informationLevel; // USHORT
	private String oldFileName;
	private String newFileName;


	SmbComNtRename(int informationLevel, String oldFileName, String newFileName)
	{
		command = SMB_COM_NT_RENAME;
		this.informationLevel = informationLevel;
		this.oldFileName = oldFileName;
		this.newFileName = newFileName;
		searchAttributes = ATTR_HIDDEN | ATTR_SYSTEM | ATTR_DIRECTORY;
	}


	int writeParameterWordsWireFormat(byte[] dst, int dstIndex)
	{
		writeInt2(searchAttributes, dst, dstIndex);
		dstIndex+=2;
		writeInt2(informationLevel, dst, dstIndex);
		dstIndex+=2;
		writeInt4(0, dst, dstIndex); // reserved

		return 8; // 4 words
	}


	int writeBytesWireFormat(byte[] dst, int dstIndex)
	{
		int start = dstIndex;

		dst[dstIndex++] = (byte) 0x04; // BufferFormat1
		dstIndex += writeString(oldFileName, dst, dstIndex);
		dst[dstIndex++] = (byte) 0x04; // BufferFormat2
		if (useUnicode)
		{
			dst[dstIndex++] = (byte) '\0';
		}
		dstIndex += writeString(newFileName, dst, dstIndex);

		return dstIndex - start;
	}


	int readParameterWordsWireFormat(byte[] buffer, int bufferIndex)
	{
		return 0;
	}


	int readBytesWireFormat(byte[] buffer, int bufferIndex)
	{
		return 0;
	}


	@Override
	public String toString()
	{
		return "SmbComNtRename[" +
		       "searchAttributes=0x" + Hexdump.toHexString(searchAttributes, 4) +
		       ",informationLevel=0x" + Hexdump.toHexString(informationLevel, 4) +
		       ",oldFileName='" + oldFileName + '\'' +
		       ",newFileName='" + newFileName + '\'' +
		       ']';
	}
}
