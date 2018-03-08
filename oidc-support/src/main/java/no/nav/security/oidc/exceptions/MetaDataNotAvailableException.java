package no.nav.security.oidc.exceptions;
/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
@SuppressWarnings("serial")
public class MetaDataNotAvailableException extends RuntimeException {
	
	public MetaDataNotAvailableException(String message){
		super(message);
	}
	public MetaDataNotAvailableException(Throwable cause){
		super(cause);
	}

}
