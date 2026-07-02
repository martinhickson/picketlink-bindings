import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable, catchError, map, of } from 'rxjs';

export interface MeResponse {
  authenticated: boolean;
  username?: string;
  roles?: string[];
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  private static readonly ME_URL = '../api/me';
  /** Full-page SAML entry when the SPA guard detects no server session. */
  static readonly SSO_ENTRY_URL = '../app/secured/';

  constructor(private http: HttpClient) {}

  me(): Observable<MeResponse> {
    return this.http.get<MeResponse>(AuthService.ME_URL);
  }

  isAuthenticated(): Observable<boolean> {
    return this.me().pipe(
      map(response => response.authenticated === true),
      catchError(() => of(false))
    );
  }

  redirectToSsoEntry(): void {
    window.location.href = AuthService.SSO_ENTRY_URL;
  }
}
