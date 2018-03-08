package no.nav.security.oidc.configuration;
/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
import java.util.Arrays;

public class IssuerMetaData {
	
	private String issuer;
	private String authorization_endpoint;
	private String token_endpoint;
	private String end_session_endpoint;
	private String jwks_uri;
	private String[] response_modes_supported;
	private String[] response_types_supported;
	private String[] scopes_supported;
	private String[] subject_types_supported;
	private String[] id_token_signing_alg_values_supported;
	private String[] token_endpoint_auth_methods_supported;
	private String[] claims_supported;
	public String getIssuer() {
		return issuer;
	}
	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}
	public String getAuthorization_endpoint() {
		return authorization_endpoint;
	}
	public void setAuthorization_endpoint(String authorization_endpoint) {
		this.authorization_endpoint = authorization_endpoint;
	}
	public String getToken_endpoint() {
		return token_endpoint;
	}
	public void setToken_endpoint(String token_endpoint) {
		this.token_endpoint = token_endpoint;
	}
	public String getEnd_session_endpoint() {
		return end_session_endpoint;
	}
	public void setEnd_session_endpoint(String end_session_endpoint) {
		this.end_session_endpoint = end_session_endpoint;
	}
	public String getJwks_uri() {
		return jwks_uri;
	}
	public void setJwks_uri(String jwks_uri) {
		this.jwks_uri = jwks_uri;
	}
	public String[] getResponse_modes_supported() {
		return response_modes_supported;
	}
	public void setResponse_modes_supported(String[] response_modes_supported) {
		this.response_modes_supported = response_modes_supported;
	}
	public String[] getResponse_types_supported() {
		return response_types_supported;
	}
	public void setResponse_types_supported(String[] response_types_supported) {
		this.response_types_supported = response_types_supported;
	}
	public String[] getScopes_supported() {
		return scopes_supported;
	}
	public void setScopes_supported(String[] scopes_supported) {
		this.scopes_supported = scopes_supported;
	}
	public String[] getSubject_types_supported() {
		return subject_types_supported;
	}
	public void setSubject_types_supported(String[] subject_types_supported) {
		this.subject_types_supported = subject_types_supported;
	}
	public String[] getId_token_signing_alg_values_supported() {
		return id_token_signing_alg_values_supported;
	}
	public void setId_token_signing_alg_values_supported(String[] id_token_signing_alg_values_supported) {
		this.id_token_signing_alg_values_supported = id_token_signing_alg_values_supported;
	}
	public String[] getToken_endpoint_auth_methods_supported() {
		return token_endpoint_auth_methods_supported;
	}
	public void setToken_endpoint_auth_methods_supported(String[] token_endpoint_auth_methods_supported) {
		this.token_endpoint_auth_methods_supported = token_endpoint_auth_methods_supported;
	}
	public String[] getClaims_supported() {
		return claims_supported;
	}
	public void setClaims_supported(String[] claims_supported) {
		this.claims_supported = claims_supported;
	}
	@Override
	public String toString() {
		return "IssuerConfiguration [issuer=" + issuer + ", authorization_endpoint=" + authorization_endpoint
				+ ", token_endpoint=" + token_endpoint + ", end_session_endpoint=" + end_session_endpoint
				+ ", jwks_uri=" + jwks_uri + ", response_modes_supported=" + Arrays.toString(response_modes_supported)
				+ ", response_types_supported=" + Arrays.toString(response_types_supported) + ", scopes_supported="
				+ Arrays.toString(scopes_supported) + ", subject_types_supported="
				+ Arrays.toString(subject_types_supported) + ", id_token_signing_alg_values_supported="
				+ Arrays.toString(id_token_signing_alg_values_supported) + ", token_endpoint_auth_methods_supported="
				+ Arrays.toString(token_endpoint_auth_methods_supported) + ", claims_supported="
				+ Arrays.toString(claims_supported) + "]";
	}
	
	
	

}
