import "pe"

rule MAL_Compromised_Cert_DarkGate_SSL_com_69DA2EDFD996EA9573C03337EF1BBC1B {
   meta:
      description         = "Detects DarkGate with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-21"
      version             = "1.0"

      hash                = "efad7bbcc8ba602d71d3c5ef68d7bcaa7c090dbfff70d3dc64e88131129ccb0a"
      malware             = "DarkGate"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware was known to be multifunctional and evasive. Its main popularity was in 2024 during a period where there were open sales. See this for more information on its functionality: https://www.proofpoint.com/us/blog/email-and-cloud-threats/darkgate-malware"

      signer              = "KHAI SON JOINT STOCK COMPANY"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "69:da:2e:df:d9:96:ea:95:73:c0:33:37:ef:1b:bc:1b"
      cert_thumbprint     = "AF0DE6BE7F26D48A0FD62B807460C0B77E68C164"
      cert_valid_from     = "2024-08-21"
      cert_valid_to       = "2025-08-21"

      country             = "VN"
      state               = "Bắc Ninh"
      locality            = "Thuan Thanh Township"
      email               = "???"
      rdn_serial_number   = "2300149170"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "69:da:2e:df:d9:96:ea:95:73:c0:33:37:ef:1b:bc:1b"
      )
}
