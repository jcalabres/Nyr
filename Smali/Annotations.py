class Annotations:
    def __init__(self, class_annotations_off, fields_size, annotated_methods_size, 
    annotated_parameters_size, field_annotations, method_annotations, parameter_annotations):
        self.class_annotations_off=class_annotations_off
        self.fields_size=fields_size
        self.annotated_methods_size=annotated_methods_size
        self.annotated_parameters_size=annotated_parameters_size
        self.field_annotations=field_annotations
        self.method_annotations=method_annotations
        self.parameter_annotations=parameter_annotations