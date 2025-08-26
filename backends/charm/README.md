# charm backend

### Prerequisites
To run this project make sure [Charm](https://github.com/JHUISI/charm) is installed.

### Restrictions
Allowed structures of literals:
- `auth.lab:attr`
- `auth.attr`
- `lab:attr`
- `attr`
Each component (auth, lab, attr) can include characters of the set `[a-zA-Z0-9@#-_]`
Allowed operators are: `and, or, AND, OR`
Note: You can mix upper- & lowercase operators and can include literals either in brackets, i.e. `()` or not


### Constructions
Currently supported constructions:
- [a_0](schemes/a_0/)
- [a_1](schemes/a_1/)
- [a_5](schemes/a_5/)
- [a_6](schemes/a_6/)

### Run scheme
If needed, change the hyperparameters in the (Main file)[main.py].
The default settings are:
```python
benchmark = False
meta_path = 'meta.json'
schemes_path = 'schemes/'
```
By default, the compiler runs all schemes
To run only a specific scheme, simply specifiy it in the `schemes_path`, e.g., `schemes_path = schemes/a_6/`

To execute the backend, simply run
```sh
python main.py
```

