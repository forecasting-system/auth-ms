export class User {
  constructor(
    public readonly id: string,
    public readonly email: string,
    public readonly name: string,
    public password: string,
  ) {}
}

export class NewUser {
  constructor(
    public readonly email: string,
    public readonly name: string,
    public readonly password: string,
  ) {}
}
