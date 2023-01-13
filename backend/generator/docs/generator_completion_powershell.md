## generator completion powershell

Generate the autocompletion script for powershell

### Synopsis

Generate the autocompletion script for powershell.

To load completions in your current shell session:

	generator completion powershell | Out-String | Invoke-Expression

To load completions for every new session, add the output of the above command
to your powershell profile.

```
generator completion powershell [flags]
```

### Options

```
  -h, --help              help for powershell
      --no-descriptions   disable completion descriptions
```

### Options inherited from parent commands

```
      --config string     config file (default is PROJECT/.env)
      --modifyExistCode   allow generator modify exist code (default true)
```

### SEE ALSO

* [generator completion](generator_completion.md)     - Generate the autocompletion script for the specified shell

###### Auto generated by spf13/cobra on 24-Jun-2022