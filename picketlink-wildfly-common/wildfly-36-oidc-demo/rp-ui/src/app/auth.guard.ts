import { inject } from '@angular/core';
import { CanActivateFn } from '@angular/router';
import { map, tap } from 'rxjs';
import { AuthService } from './auth.service';

/** Server-backed guard: only allow secured routes when {@code GET /api/me} succeeds. */
export const authGuard: CanActivateFn = () => {
  const auth = inject(AuthService);
  return auth.isAuthenticated().pipe(
    tap(ok => {
      if (!ok) {
        auth.redirectToOidcLogin();
      }
    }),
    map(ok => ok)
  );
};
