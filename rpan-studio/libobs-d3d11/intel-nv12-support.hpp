static bool IsOldIntelPlatform(uint32_t device_id)
{
	switch (device_id) {
	/*IVB*/
	case 0x0152:
	case 0x0156:
	case 0x015A:
	case 0x0162:
	case 0x0166:
	case 0x016A:
	case 0x0172:
	case 0x0176:
	case 0x0182:
	case 0x0186:
		return true;

	/* VLV */
	case 0x0f30:
	case 0x0f31:
	case 0x0f32:
	case 0x0f33:
	case 0x0157:
	case 0x0155:
		return true;

	/*HSW*/
	case 0x0090:
	case 0x0091:
	case 0x0092:
	case 0x0094:
	case 0x0C02:
	case 0x0C06:
	case 0x0C12:
	case 0x0C16:
	case 0x0C22:
	case 0x0C26:
	case 0x0C0B:
	case 0x0402:
	case 0x0406:
	case 0x040A:
	case 0x040B:
	case 0x040E:
	case 0x0412:
	case 0x0416:
	case 0x041A:
	case 0x041B:
	case 0x041E:
	case 0x0422:
	case 0x0426:
	case 0x042A:
	case 0x042B:
	case 0x042E:
	case 0x0A02:
	case 0x0A06:
	case 0x0A0A:
	case 0x0A0B:
	case 0x0A0E:
	case 0x0A12:
	case 0x0A16:
	case 0x0A1A:
	case 0x0A1B:
	case 0x0A1E:
	case 0x0A22:
	case 0x0A26:
	case 0x0A2A:
	case 0x0A2B:
	case 0x0A2E:
		return true;

	/* CRW */
	case 0x0D02:
	case 0x0D06:
	case 0x0D0A:
	case 0x0D0B:
	case 0x0D0E:
	case 0x0D12:
	case 0x0D16:
	case 0x0D1A:
	case 0x0D1B:
	case 0x0D1E:
	case 0x0D22:
	case 0x0D26:
	case 0x0D2A:
	case 0x0D2B:
	case 0x0D2E:
		return true;

	/* BDW */
	case 0x1602:
	case 0x1606:
	case 0x160A:
	case 0x160B:
	case 0x160D:
	case 0x160E:
	case 0x1612:
	case 0x1616:
	case 0x161A:
	case 0x161B:
	case 0x161D:
	case 0x161E:
	case 0x1622:
	case 0x1626:
	case 0x162A:
	case 0x162B:
	case 0x162D:
	case 0x162E:
	case 0x1632:
	case 0x1636:
	case 0x163A:
	case 0x163B:
	case 0x163D:
	case 0x163E:
	case 0x0BD0:
	case 0x0BD1:
	case 0x0BD2:
	case 0x0BD3:
	case 0x0BD4:
		return true;

	/* CHT */
	case 0x22b0:
	case 0x22b1:
	case 0x22b2:
	case 0x22b3:
		return true;

	/* SKL */
	case 0x0900:
	case 0x0901:
	case 0x0902:
	case 0x0903:
	case 0x0904:
	case 0x1902:
	case 0x1906:
	case 0x190A:
	case 0x190B:
	case 0x190E:
	case 0x1913:
	case 0x1915:
	case 0x1917:
	case 0x1912:
	case 0x1916:
	case 0x191A:
	case 0x191B:
	case 0x191D:
	case 0x191E:
	case 0x1921:
	case 0x1923:
	case 0x1926:
	case 0x1927:
	case 0x192A:
	case 0x192B:
	case 0x192D:
	case 0x1932:
	case 0x193A:
	case 0x193B:
	case 0x193D:
	case 0x9905:
		return true;

	/* GLK */
	case 0x3184:
	case 0x3185:
		return true;

	/* APL */
	case 0x9906:
	case 0x9907:
	case 0x9908:
	case 0x0A84:
	case 0x0A85:
	case 0x0A86:
	case 0x0A87:
	case 0x1A84:
	case 0x1A85:
	case 0x5A84:
	case 0x5A85:
		return true;

	/* KBL */
	case 0x5902:
	case 0x5906:
	case 0x5908:
	case 0x590A:
	case 0x590B:
	case 0x590E:
	case 0x5912:
	case 0x5913:
	case 0x5915:
	case 0x5916:
	case 0x5917:
	case 0x591A:
	case 0x591B:
	case 0x591C:
	case 0x591D:
	case 0x591E:
	case 0x5921:
	case 0x5923:
	case 0x5926:
	case 0x5927:
	case 0x592A:
	case 0x592B:
	case 0x5932:
	case 0x593A:
	case 0x593B:
	case 0x593D:
	case 0x87C0:
		return true;

	/* CFL */
	case 0x3E04:
	case 0x3E90:
	case 0x3E91:
	case 0x3E92:
	case 0x3E93:
	case 0x3E94:
	case 0x3E96:
	case 0x3E98:
	case 0x3E99:
	case 0x3E9A:
	case 0x3E9C:
	case 0x3E9B:
	case 0x3EA5:
	case 0x3EA6:
	case 0x3EA7:
	case 0x3EA8:
	case 0x3EA9:
	case 0x5B04:
	case 0x87CA:
		return true;

	/* WHL */
	case 0x3EA0:
	case 0x3EA1:
	case 0x3EA2:
	case 0x3EA3:
	case 0x3EA4:
		return true;

	/* CML */
	case 0x9b21:
	case 0x9baa:
	case 0x9bab:
	case 0x9bac:
	case 0x9ba0:
	case 0x9ba5:
	case 0x9ba8:
	case 0x9ba4:
	case 0x9ba2:
	case 0x9b41:
	case 0x9bca:
	case 0x9bcb:
	case 0x9bcc:
	case 0x9bc0:
	case 0x9bc5:
	case 0x9bc8:
	case 0x9bc4:
	case 0x9bc2:
	case 0x9bc6:
	case 0x9be6:
	case 0x9bf6:
		return true;

	/* CNL */
	case 0x0A01:
	case 0x0A00:
	case 0x0A05:
	case 0x0A07:
	case 0x5A40:
	case 0x5A50:
	case 0x5A60:
	case 0x5A70:
	case 0x5A41:
	case 0x5A51:
	case 0x5A61:
	case 0x5A71:
	case 0x5A42:
	case 0x5A52:
	case 0x5A62:
	case 0x5A72:
	case 0x5A43:
	case 0x5A53:
	case 0x5A63:
	case 0x5A73:
	case 0x5A45:
	case 0x5A55:
	case 0x5A65:
	case 0x5A75:
	case 0x5A46:
	case 0x5A56:
	case 0x5A66:
	case 0x5A76:
	case 0x5A47:
	case 0x5A57:
	case 0x5A67:
	case 0x5A77:
	case 0x5A58:
	case 0x5A68:
	case 0x5A78:
	case 0x5A49:
	case 0x5A59:
	case 0x5A79:
	case 0x5A4A:
	case 0x5A5A:
	case 0x5A6A:
	case 0x5A7A:
	case 0x5A6B:
	case 0x5A4D:
	case 0x5A5D:
	case 0x5A44:
	case 0x5A54:
	case 0x5A64:
	case 0x5A74:
	case 0x5A4C:
	case 0x5A5C:
		return true;

	/* ICL or later platforms */
	default:
		return false;
	}
}
