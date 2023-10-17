### Configuration control via: config.py
- #### default config file : ../config.json
-------
### Logs print via : logger.py

```python
        COLORS:
            REST
            GREEN  
            YELLOW 
            RED    
            WHITE
        Logger.msg("[ANY COLOR] hello, wolrd!")
        Logger.msg("[RED]he[YELLOW]llo[REST], wolrd!")
```
> ${\color{red}He \color{yellow}llo \color{white}, world!}$
<br>

   by default `Logger.msg(message: str)` will add [REST] at the end so no need to write [REST] at the end of message.<br>
   E.g:
  ```python
    Logger.msg("[RED]Hello")      # will be : Logger.msg("[RED]Hello[REST]")
    Logger.msg(", wolrd!")        # will be : Logger.msg(", wolrd![REST]")
    # without colors
    Logger.msg("Hello, world!")   # will be : Logger.msg("Hello, world![REST]")
  ```

 >  ${\color{red}Hello \color{white}, world!}$ <br>
 > ${\color{white}Hello, world!}$



