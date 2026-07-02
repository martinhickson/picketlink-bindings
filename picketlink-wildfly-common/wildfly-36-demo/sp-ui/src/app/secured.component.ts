import { Component, HostListener, inject, OnInit } from '@angular/core';
import { AsyncPipe, JsonPipe } from '@angular/common';
import { AuthService } from './auth.service';
import { BehaviorSubject, switchMap } from 'rxjs';

@Component({
  standalone: true,
  imports: [AsyncPipe, JsonPipe],
  template: `
    <div class="card">
      <h1>Secured SP Area</h1>
      <p>Access is gated by the server: this view loads only when <code>GET /api/me</code> returns authenticated.</p>
      @if (me$ | async; as me) {
        <p>Signed in as <strong>{{ me.username }}</strong> (roles: {{ me.roles | json }}).</p>
      }
      <div class="grid">
        <a class="btn" href="../app/secured/logout?GLO=true">Global logout (SP + IDP)</a>
        <a class="btn btn-secondary" href="../app/secured/logout?LLO=true">Local logout (SP only)</a>
        <a class="btn btn-secondary" href="../app/secured/">Reload secured page</a>
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
        this.auth.redirectToSsoEntry();
        return;
      }
      this.refresh$.next();
    });
  }
}
