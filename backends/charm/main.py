from CharmBackend import handler

# Hyperparams
meta_path = 'schemes/meta.json'
schemes_path = 'schemes/' # "schemes/a_X" to run specific scheme
benchmark = False

handler.run_scheme(meta_path=meta_path, 
                   schemes_path=schemes_path, 
                   benchmark=benchmark)
