import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable, catchError, map, of } from 'rxjs';

export interface MeResponse {
  authenticated: boolean;
  username?: string;
  roles?: string[];
  tokenType?: string;
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  private static readonly ME_URL = '../api/me';
  /** Full-page OIDC Authorization Code entry (CXF filter redirects to AS). */
  static readonly OIDC_ENTRY_URL = '../api/me';

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

  redirectToOidcLogin(): void {
    window.location.href = AuthService.OIDC_ENTRY_URL;
  }
}
