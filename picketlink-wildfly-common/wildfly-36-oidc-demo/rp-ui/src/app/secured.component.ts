import { Component, HostListener, inject, OnInit } from '@angular/core';
import { AsyncPipe, JsonPipe } from '@angular/common';
import { AuthService } from './auth.service';
import { BehaviorSubject, switchMap } from 'rxjs';

@Component({
  standalone: true,
  imports: [AsyncPipe, JsonPipe],
  template: `
    <div class="card">
      <h1>Secured RP Area (OIDC)</h1>
      <p>Access requires a valid OIDC token from the Authorization Server (Authorization Code flow).</p>
      @if (me$ | async; as me) {
        <p>Signed in as <strong>{{ me.username }}</strong> via {{ me.tokenType }} (roles: {{ me.roles | json }}).</p>
      }
      <div class="grid">
        <a class="btn" href="../api/me">Re-authenticate via OIDC</a>
        <a class="btn btn-secondary" href="../LogoutServlet?GLO=true">Global logout (RP + AS)</a>
        <a class="btn btn-secondary" href="../LogoutServlet?LLO=true">Local logout (RP only)</a>
        <a class="btn btn-secondary" href="../app/">Back to home</a>
      </div>
    </div>
  `
})
export class SecuredComponent implements OnInit {
  private auth = inject(AuthService);
  private refresh$ = new BehaviorSubject<void>(undefined);
  me$ = this.refresh$.pipe(switchMap(() => this.auth.me()));

  ngOnInit(): void {
    this.verifySession();
  }

  @HostListener('window:focus')
  onFocus(): void {
    this.verifySession();
  }

  private verifySession(): void {
    this.auth.isAuthenticated().subscribe(ok => {
      if (!ok) {
        this.auth.redirectToOidcLogin();
        return;
      }
      this.refresh$.next();
    });
  }
}
