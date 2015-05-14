package aes;

// This is to select the AES algorithm which will be used.
public enum AES_Length
{
	//This int value assigned is for later use in the algorithm. This value is called Nk in the standard.
	AES_128(4, 4, 10),
	AES_192(6, 4, 12),
	AES_256(8, 4, 14);
	
	// This holds the enum value.
	private final int Nk;
	private final int Nb;
	private final int Nr;
	
	// This is the enum constructor.
	AES_Length(int Nk, int Nb, int Nr)
	{
		this.Nk = Nk;
		this.Nb = Nb;
		this.Nr = Nr;
	}
	
	public int Nk()
	{
		return Nk;
	}
	
	public int Nb()
	{
		return Nb;
	}
	
	public int Nr()
	{
		return Nr;
	}
}