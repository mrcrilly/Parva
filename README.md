Parva
=====

Parva is designed to be a small, simple CLI based password manager with three strict security objectives:

- A strict password policy enforcing long, complicated passwords. Default of 50 characters long with symbols;
- Automatically generated passwords based on the policy: the user cannot define their own passwords, thus enforcing the policy, preventing insecure or undesirable passwords;
- Expiring and auto-renewing passwords prevent secrets from getting stale. The password will automatically rotate when it reaches the expiry date, saving the last generation;

I believe that Parva, combined with a small degree of discipline, will help the more paranoid amongst us manage their passwords in a more secure, compact and portable manner, without needlessly compromising security in the name of "convenience."

The project features:

- Flat file database encrypted with AES-256 in CFB mode - very easy backups and portability;
- All data is in JSON, so it's super easy to import elsewhere if desired;
- Automatic backup of database when a write operation is performed;
- Edit the policy from the CLI, changing the default password length, use of symbols and number of days each password expires;

Features to come:

- Basic REST API using Bottle;
- Remote database storage, downloaded over HTTP(S);
